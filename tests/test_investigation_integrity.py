import hashlib
import json

from astranyx.investigation import integrity


def write_manifest(workspace, artifacts):
    (workspace / "manifest.json").write_text(
        json.dumps(
            {
                "investigation": {"id": "INV-TEST"},
                "artifacts": artifacts,
            }
        )
    )


def record(path, workspace):
    content = path.read_bytes()
    return {
        "path": path.relative_to(workspace).as_posix(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_verify_accepts_intact_investigation(tmp_path):
    artifact = tmp_path / "reports" / "report.json"
    artifact.parent.mkdir()
    artifact.write_text('{"finding": "validated"}')
    write_manifest(tmp_path, [record(artifact, tmp_path)])

    result = integrity.verify(tmp_path)

    assert result["valid"] is True
    assert result["investigation_id"] == "INV-TEST"
    assert result["artifacts_checked"] == 1
    assert result["failures"] == []


def test_verify_reports_modified_and_missing_artifacts(tmp_path):
    modified = tmp_path / "modified.txt"
    modified.write_text("original")
    records = [
        record(modified, tmp_path),
        {
            "path": "missing.txt",
            "size_bytes": 1,
            "sha256": "0" * 64,
        },
    ]
    write_manifest(tmp_path, records)
    modified.write_text("changed")

    result = integrity.verify(tmp_path)

    assert result["valid"] is False
    reasons = [failure["reason"] for failure in result["failures"]]
    assert "size mismatch" in reasons
    assert "SHA-256 mismatch" in reasons
    assert any(reason.startswith("unreadable:") for reason in reasons)


def test_verify_rejects_unsafe_and_duplicate_paths(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("evidence")
    artifact_record = record(artifact, tmp_path)
    write_manifest(
        tmp_path,
        [artifact_record, artifact_record, {"path": "../outside", "size_bytes": 0}],
    )

    result = integrity.verify(tmp_path)

    assert result["valid"] is False
    assert [failure["reason"] for failure in result["failures"]] == [
        "duplicate artifact path",
        "unsafe artifact path",
    ]
