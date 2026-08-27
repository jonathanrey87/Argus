import json
import subprocess
from datetime import UTC, datetime

import pytest

from astranyx.device import ios


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_doctor_reports_missing_optional_dependency():
    result = ios.doctor(which=lambda _: None)

    assert result == {
        "collector": "pymobiledevice3",
        "installed": False,
        "device_detected": False,
        "ready": False,
        "detail": "pymobiledevice3 is not installed",
    }


def test_snapshot_redacts_identifiers_and_writes_manifest(tmp_path):
    responses = iter(
        [
            completed(
                json.dumps(
                    {
                        "DeviceName": "Researcher's iPhone",
                        "SerialNumber": "secret-serial",
                        "ProductType": "iPhone18,2",
                        "ProductVersion": "26.0",
                        "BuildVersion": "23A1",
                    }
                )
            ),
            completed(
                json.dumps(
                    {
                        "com.apple.mobilesafari": {
                            "CFBundleDisplayName": "Safari",
                            "CFBundleShortVersionString": "26.0",
                        }
                    }
                )
            ),
        ]
    )

    path = ios.snapshot(
        tmp_path,
        runner=lambda _: next(responses),
        which=lambda _: "/usr/bin/pymobiledevice3",
        now=lambda: datetime(2026, 8, 25, 12, 0, tzinfo=UTC),
    )

    payload = json.loads(path.read_text())
    assert payload["collection_mode"] == "read-only"
    assert payload["device"]["ProductType"] == "iPhone18,2"
    assert payload["device"]["DeviceName"].startswith("<redacted:sha256:")
    assert payload["device"]["SerialNumber"].startswith("<redacted:sha256:")
    assert payload["applications"][0]["bundle_id"] == "com.apple.mobilesafari"
    assert payload["assessment"]["standard_configuration"] == "not_assessed"

    manifest = json.loads(
        path.with_name("ios-snapshot-20260825T120000Z.manifest.json").read_text()
    )
    assert manifest["artifact"] == path.name
    assert len(manifest["sha256"]) == 64
    assert manifest["size"] == path.stat().st_size


def test_snapshot_does_not_store_non_json_raw_output(tmp_path):
    message = "no raw device data was stored"
    with pytest.raises(ios.DeviceCollectionError, match=message):
        ios.snapshot(
            tmp_path,
            runner=lambda _: completed("private raw output"),
            which=lambda _: "/usr/bin/pymobiledevice3",
        )
    assert not (tmp_path / "device").exists()


def test_snapshot_refuses_to_overwrite_evidence(tmp_path):
    moment = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    evidence = tmp_path / "device"
    evidence.mkdir()
    (evidence / "ios-snapshot-20260825T120000Z.json").write_text("existing")
    responses = iter([completed("{}"), completed("{}")])

    with pytest.raises(ios.DeviceCollectionError, match="refusing to overwrite"):
        ios.snapshot(
            tmp_path,
            runner=lambda _: next(responses),
            which=lambda _: "/usr/bin/pymobiledevice3",
            now=lambda: moment,
        )


def test_snapshot_refuses_to_overwrite_existing_manifest(tmp_path):
    moment = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    evidence = tmp_path / "device"
    evidence.mkdir()
    manifest = evidence / "ios-snapshot-20260825T120000Z.manifest.json"
    manifest.write_text("existing")

    with pytest.raises(ios.DeviceCollectionError, match="refusing to overwrite"):
        ios.snapshot(
            tmp_path,
            runner=lambda _: completed("{}"),
            which=lambda _: "/usr/bin/pymobiledevice3",
            now=lambda: moment,
        )

    assert manifest.read_text() == "existing"


def test_compare_snapshots_reports_application_changes(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(
        json.dumps(
            {
                "device": {"ProductVersion": "26.0"},
                "applications": [
                    {"bundle_id": "a", "version": "1"},
                    {"bundle_id": "removed", "version": "1"},
                ],
            }
        )
    )
    after.write_text(
        json.dumps(
            {
                "device": {"ProductVersion": "26.1"},
                "applications": [
                    {"bundle_id": "a", "version": "2"},
                    {"bundle_id": "added", "version": "1"},
                ],
            }
        )
    )

    result = ios.compare_snapshots(before, after)

    assert result["device_changed"] is True
    assert [item["bundle_id"] for item in result["applications_added"]] == ["added"]
    assert [item["bundle_id"] for item in result["applications_removed"]] == ["removed"]
    assert result["applications_changed"][0]["bundle_id"] == "a"


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "root must be an object"),
        ({"device": [], "applications": []}, "device must be an object"),
        ({"device": {}, "applications": {}}, "applications must be a list"),
        ({"device": {}, "applications": ["not-an-app"]}, "list of objects"),
    ],
)
def test_compare_snapshots_rejects_malformed_evidence(tmp_path, payload, message):
    malformed = tmp_path / "malformed.json"
    valid = tmp_path / "valid.json"
    malformed.write_text(json.dumps(payload))
    valid.write_text(json.dumps({"device": {}, "applications": []}))

    with pytest.raises(ios.DeviceCollectionError, match=message):
        ios.compare_snapshots(malformed, valid)


def test_verify_snapshot_detects_modified_evidence(tmp_path):
    responses = iter([completed("{}"), completed("{}")])
    path = ios.snapshot(
        tmp_path,
        runner=lambda _: next(responses),
        which=lambda _: "/usr/bin/pymobiledevice3",
    )

    verified = ios.verify_snapshot(path)
    assert verified["verified"] is True
    assert verified["sha256"] == ios._sha256(path)

    path.write_text(path.read_text() + " ")
    with pytest.raises(ios.DeviceCollectionError, match="size mismatch"):
        ios.verify_snapshot(path)


def test_compare_rejects_snapshot_with_invalid_sidecar(tmp_path):
    snapshot = tmp_path / "ios-snapshot-before.json"
    other = tmp_path / "after.json"
    payload = json.dumps({"device": {}, "applications": []})
    snapshot.write_text(payload)
    other.write_text(payload)
    snapshot.with_name("ios-snapshot-before.manifest.json").write_text(
        json.dumps(
            {
                "artifact": snapshot.name,
                "size": snapshot.stat().st_size,
                "sha256": "0" * 64,
            }
        )
    )

    with pytest.raises(ios.DeviceCollectionError, match="SHA-256 mismatch"):
        ios.compare_snapshots(snapshot, other)
