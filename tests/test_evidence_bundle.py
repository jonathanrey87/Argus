import json
import sys

import pytest

from astranyx.cli import main
from astranyx.evidence import (
    EvidenceError,
    capture_bundle,
    compare_bundles,
    verify_bundle,
)


def write_plan(path, plan_id="vp-1234567890abcdefabcd"):
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "execution_allowed": False,
                "plans": [
                    {
                        "id": plan_id,
                        "status": "planned",
                        "execution_allowed": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_capture_redacts_secrets_and_seals_bundle(tmp_path):
    plan = tmp_path / "plan.json"
    source = tmp_path / "request.txt"
    bundle = tmp_path / "bundle"
    write_plan(plan)
    source.write_text(
        'Authorization: Bearer secret-value\npassword=hunter2\n"authorization": "Bearer json-secret"\nhttps://user:pass@example.test/a?token=secret',
        encoding="utf-8",
    )
    result = capture_bundle(plan, [source], bundle)
    stored = (bundle / "evidence" / "artifact-0001.txt").read_text()
    assert result["redactions"] == 5
    assert "secret-value" not in stored
    assert "hunter2" not in stored
    assert "json-secret" not in stored
    assert "user:pass" not in stored
    assert "token=%5BREDACTED%5D" in stored
    assert verify_bundle(bundle)["valid"]


def test_verify_detects_artifact_and_manifest_tampering(tmp_path):
    plan = tmp_path / "plan.json"
    source = tmp_path / "evidence.txt"
    write_plan(plan)
    source.write_text("bounded evidence")
    first = tmp_path / "first"
    capture_bundle(plan, [source], first)
    (first / "evidence" / "artifact-0001.txt").write_text("tampered")
    assert not verify_bundle(first)["valid"]

    second = tmp_path / "second"
    capture_bundle(plan, [source], second)
    manifest = json.loads((second / "manifest.json").read_text())
    manifest["plan_id"] = "vp-tampered"
    (second / "manifest.json").write_text(json.dumps(manifest))
    result = verify_bundle(second)
    assert not result["valid"]
    assert result["failures"][0]["reason"] == "seal mismatch"


def test_verify_rejects_symlink_substitution(tmp_path):
    plan = tmp_path / "plan.json"
    source = tmp_path / "evidence.txt"
    outside = tmp_path / "outside.txt"
    bundle = tmp_path / "bundle"
    write_plan(plan)
    source.write_text("original")
    outside.write_text("replacement")
    capture_bundle(plan, [source], bundle)
    artifact = bundle / "evidence" / "artifact-0001.txt"
    artifact.unlink()
    artifact.symlink_to(outside)
    with pytest.raises(EvidenceError, match="symbolic"):
        verify_bundle(bundle)


def test_compare_classifies_retest_evidence(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    source = tmp_path / "response.txt"
    source.write_text("before")
    before = tmp_path / "before"
    capture_bundle(plan, [source], before)
    source.write_text("after")
    after = tmp_path / "after"
    capture_bundle(plan, [source], after)
    result = compare_bundles(before, after)
    assert result["summary"] == {"added": 0, "removed": 0, "changed": 1, "unchanged": 0}
    assert result["changed"] == ["response.txt"]


def test_rejects_binary_symlink_duplicate_and_ambiguous_plan(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    binary = tmp_path / "binary.bin"
    binary.write_bytes(b"\xff\xfe")
    with pytest.raises(EvidenceError, match="UTF-8"):
        capture_bundle(plan, [binary], tmp_path / "binary-bundle")

    source = tmp_path / "source.txt"
    source.write_text("evidence")
    link = tmp_path / "link.txt"
    link.symlink_to(source)
    with pytest.raises(EvidenceError, match="non-symlink"):
        capture_bundle(plan, [link], tmp_path / "link-bundle")
    with pytest.raises(EvidenceError, match="duplicate"):
        capture_bundle(plan, [source, source], tmp_path / "duplicate-bundle")


def test_cli_capture_and_verify(tmp_path, monkeypatch, capsys):
    plan = tmp_path / "plan.json"
    source = tmp_path / "evidence.txt"
    bundle = tmp_path / "bundle"
    write_plan(plan)
    source.write_text("token=secret")
    monkeypatch.setattr(
        sys,
        "argv",
        ["astranyx", "evidence", "capture", str(plan), str(source), "-o", str(bundle)],
    )
    main()
    assert json.loads(capsys.readouterr().out)["artifacts"] == 1
    monkeypatch.setattr(sys, "argv", ["astranyx", "evidence", "verify", str(bundle)])
    main()
    assert json.loads(capsys.readouterr().out)["valid"] is True
