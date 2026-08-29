import hashlib
import json
import sys

import pytest

from astranyx.cli import main
from astranyx.investigation import orchestrator


def _write_web_target(root):
    target = root / "authorized-target"
    assets = target / "assets"
    assets.mkdir(parents=True)

    (assets / "app.js").write_text(
        'fetch("/api/profile");',
        encoding="utf-8",
    )
    (target / "plugin.php").write_text(
        "<?php add_action('wp_ajax_nopriv_demo', 'demo');",
        encoding="utf-8",
    )
    return target


def test_select_modules_for_web_target(tmp_path):
    target = _write_web_target(tmp_path)

    assert orchestrator.select_modules(target, "auto") == [
        "javascript",
        "wordpress",
    ]
    assert orchestrator.select_modules(target, "javascript") == ["javascript"]
    assert orchestrator.select_modules(target, "wordpress") == ["wordpress"]

    with pytest.raises(ValueError, match="No analyzable"):
        orchestrator.select_modules(
            target,
            "javascript",
            recursive=False,
        )


def test_select_modules_rejects_empty_target(tmp_path):
    target = tmp_path / "empty"
    target.mkdir()

    with pytest.raises(ValueError, match="No analyzable"):
        orchestrator.select_modules(target)


def test_investigation_pipeline_generates_hashed_manifest(tmp_path):
    target = _write_web_target(tmp_path)
    workspace_root = tmp_path / "investigations"

    result = orchestrator.run(
        target,
        profile="web",
        workspace_root=workspace_root,
    )

    workspace = result["workspace"]
    metadata = json.loads((workspace / "metadata.json").read_text())
    manifest = json.loads((workspace / "manifest.json").read_text())

    assert result["status"] == "completed"
    assert metadata["status"] == "completed"
    assert metadata["profile"] == "web"
    assert metadata["selected_modules"] == ["javascript", "wordpress"]
    assert [module["name"] for module in metadata["modules"]] == [
        "javascript",
        "wordpress",
    ]
    assert (workspace / "analysis" / "javascript.json").is_file()
    assert (workspace / "analysis" / "findings.json").is_file()
    assert (workspace / "analysis" / "evidence-graph.json").is_file()
    assert (workspace / "reports" / "wordpress" / "index.html").is_file()
    assert manifest["investigation"]["status"] == "completed"
    assert manifest["failures"] == []
    assert manifest["deduplication"]["artifact"] == "analysis/findings.json"
    assert manifest["deduplication"]["observations"] >= 1
    assert manifest["evidence_graph"]["artifact"] == (
        "analysis/evidence-graph.json"
    )
    assert manifest["evidence_graph"]["nodes"] >= 1

    for artifact in manifest["artifacts"]:
        artifact_path = workspace / artifact["path"]
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        assert artifact["sha256"] == digest


def test_investigation_pipeline_isolates_module_failure(
    tmp_path,
    monkeypatch,
):
    target = _write_web_target(tmp_path)

    def fail_wordpress(*_args, **_kwargs):
        raise RuntimeError("test analyzer failure")

    monkeypatch.setattr(
        orchestrator,
        "_run_wordpress",
        fail_wordpress,
    )

    result = orchestrator.run(
        target,
        profile="web",
        workspace_root=tmp_path / "investigations",
    )

    metadata = json.loads(
        (result["workspace"] / "metadata.json").read_text(encoding="utf-8")
    )

    assert result["status"] == "partial"
    assert result["failures"] == [
        {
            "module": "wordpress",
            "error_type": "RuntimeError",
            "message": "test analyzer failure",
        }
    ]
    assert metadata["status"] == "partial"
    assert metadata["modules"][-1]["status"] == "failed"


def test_investigate_cli_runs_target_pipeline(
    tmp_path,
    monkeypatch,
):
    target = _write_web_target(tmp_path)
    workspace_root = tmp_path / "cli-investigations"

    monkeypatch.delenv("ARIZE_SPACE_ID", raising=False)
    monkeypatch.delenv("ARIZE_API_KEY", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "astranyx",
            "investigate",
            str(target),
            "--profile",
            "javascript",
            "--workspace-root",
            str(workspace_root),
        ],
    )

    main()

    workspaces = list(workspace_root.glob("INV-*"))
    assert len(workspaces) == 1

    metadata = json.loads((workspaces[0] / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "completed"
    assert metadata["selected_modules"] == ["javascript"]
    assert [module["name"] for module in metadata["modules"]] == ["javascript"]
    assert metadata["modules"][0]["status"] == "completed"


def test_resume_retries_only_failed_modules(tmp_path, monkeypatch):
    target = _write_web_target(tmp_path)
    original_wordpress = orchestrator._run_wordpress
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("interrupted analyzer")
        return original_wordpress(*args, **kwargs)

    monkeypatch.setattr(orchestrator, "_run_wordpress", fail_once)
    initial = orchestrator.run(
        target,
        profile="web",
        workspace_root=tmp_path / "investigations",
    )
    javascript_before = (
        initial["workspace"] / "analysis" / "javascript.json"
    ).read_bytes()

    resumed = orchestrator.resume(initial["workspace"])

    metadata = json.loads(
        (initial["workspace"] / "metadata.json").read_text(encoding="utf-8")
    )
    assert resumed["status"] == "completed"
    assert attempts == 2
    assert resumed["failures"] == []
    assert set(resumed["module_results"]) == {"javascript", "wordpress"}
    assert (
        initial["workspace"] / "analysis" / "javascript.json"
    ).read_bytes() == javascript_before
    assert metadata["resumes"][0]["prior_status"] == "partial"
    assert metadata["resumes"][0]["modules"] == ["wordpress"]


def test_resume_rejects_modified_completed_artifact(tmp_path, monkeypatch):
    target = _write_web_target(tmp_path)

    def fail_wordpress(*_args, **_kwargs):
        raise RuntimeError("interrupted analyzer")

    monkeypatch.setattr(orchestrator, "_run_wordpress", fail_wordpress)
    initial = orchestrator.run(
        target,
        profile="web",
        workspace_root=tmp_path / "investigations",
    )
    (initial["workspace"] / "analysis" / "javascript.json").write_text(
        "tampered", encoding="utf-8"
    )

    with pytest.raises(
        orchestrator.integrity.IntegrityError,
        match="failed integrity verification",
    ):
        orchestrator.resume(initial["workspace"])


def test_resume_rejects_completed_investigation(tmp_path):
    target = _write_web_target(tmp_path)
    initial = orchestrator.run(
        target,
        profile="javascript",
        workspace_root=tmp_path / "investigations",
    )

    with pytest.raises(ValueError, match="already complete"):
        orchestrator.resume(initial["workspace"])


def test_resume_rejects_metadata_that_differs_from_seal(tmp_path, monkeypatch):
    target = _write_web_target(tmp_path)
    monkeypatch.setattr(
        orchestrator,
        "_run_wordpress",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("stopped")),
    )
    initial = orchestrator.run(
        target,
        profile="web",
        workspace_root=tmp_path / "investigations",
    )
    metadata_path = initial["workspace"] / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["profile"] = "auto"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(
        orchestrator.integrity.IntegrityError,
        match="context does not match metadata: profile",
    ):
        orchestrator.resume(initial["workspace"])


def test_investigate_cli_resumes_workspace(tmp_path, monkeypatch):
    target = _write_web_target(tmp_path)
    original_wordpress = orchestrator._run_wordpress

    monkeypatch.setattr(
        orchestrator,
        "_run_wordpress",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("stopped")),
    )
    initial = orchestrator.run(
        target,
        profile="web",
        workspace_root=tmp_path / "investigations",
    )
    monkeypatch.setattr(orchestrator, "_run_wordpress", original_wordpress)
    monkeypatch.setattr(
        sys,
        "argv",
        ["astranyx", "investigate", "--resume", str(initial["workspace"])],
    )

    main()

    metadata = json.loads(
        (initial["workspace"] / "metadata.json").read_text(encoding="utf-8")
    )
    assert metadata["status"] == "completed"
