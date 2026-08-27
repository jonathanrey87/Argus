"""Read-only iOS inventory collection through ``pymobiledevice3``.

The collector intentionally exposes no commands that mutate device state.  It
stores normalized, redacted evidence inside an Astranyx investigation rather
than retaining raw device output in a shared location.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
TOOL = "pymobiledevice3"
SENSITIVE_KEY = re.compile(
    r"(apple.?id|device.?name|e.?mail|host.?id|iccid|imei|meid|phone|serial|udid|"
    r"unique.?chip|unique.?device)",
    re.IGNORECASE,
)


class DeviceCollectionError(RuntimeError):
    """Raised when read-only device evidence cannot be collected."""


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _find_tool(which: Callable[[str], str | None]) -> str | None:
    executable = which(TOOL)
    if executable:
        return executable
    sibling = Path(sys.executable).with_name(TOOL)
    return str(sibling) if sibling.is_file() else None


def _error_detail(result: subprocess.CompletedProcess[str]) -> str:
    output = result.stderr.strip() or result.stdout.strip() or "unknown error"
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1][:500] if lines else "unknown error"


def _digest(value: Any) -> str:
    encoded = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest()[:12]


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact identifiers while retaining correlation tokens."""
    if SENSITIVE_KEY.search(key) and value not in (None, ""):
        return f"<redacted:sha256:{_digest(value)}>"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _json_output(result: subprocess.CompletedProcess[str], label: str) -> Any:
    if result.returncode != 0:
        raise DeviceCollectionError(f"{label} failed: {_error_detail(result)}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DeviceCollectionError(
            f"{label} did not return JSON; no raw device data was stored"
        ) from exc


def doctor(
    *,
    runner: Runner = _run,
    which: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    """Check whether the optional collector and a trusted device are available."""
    executable = _find_tool(which)
    result: dict[str, Any] = {
        "collector": TOOL,
        "installed": executable is not None,
        "device_detected": False,
        "ready": False,
        "detail": "",
    }
    if executable is None:
        result["detail"] = "pymobiledevice3 is not installed"
        return result

    probe = runner([executable, "usbmux", "list"])
    if probe.returncode != 0:
        result["detail"] = _error_detail(probe)
        return result

    output = probe.stdout.strip()
    if not output or output in ("[]", "{}"):
        result["detail"] = "no trusted USB device detected"
        return result

    result.update(
        device_detected=True,
        ready=True,
        detail="trusted USB device detected",
    )
    return result


def _normalize_apps(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        records = []
        for bundle_id, details in payload.items():
            item = details if isinstance(details, dict) else {"value": details}
            records.append({**item, "bundle_id": bundle_id})
    elif isinstance(payload, list):
        records = [item for item in payload if isinstance(item, dict)]
    else:
        raise DeviceCollectionError("application inventory has an unexpected shape")

    return sorted(
        (redact(item) for item in records),
        key=lambda item: str(
            item.get("bundle_id")
            or item.get("CFBundleIdentifier")
            or item.get("BundleIdentifier")
            or ""
        ),
    )


def _write_json(path: Path, payload: Any) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_path(snapshot_path: Path) -> Path:
    return snapshot_path.with_name(f"{snapshot_path.stem}.manifest.json")


def verify_snapshot(snapshot: str | Path) -> dict[str, Any]:
    """Verify a snapshot against its sidecar integrity manifest."""
    snapshot_path = Path(snapshot)
    manifest_path = _manifest_path(snapshot_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        actual_size = snapshot_path.stat().st_size
        actual_digest = _sha256(snapshot_path)
    except (OSError, json.JSONDecodeError) as exc:
        raise DeviceCollectionError(f"unable to verify snapshot: {exc}") from exc

    if not isinstance(manifest, dict):
        raise DeviceCollectionError(
            f"invalid manifest {manifest_path}: root must be an object"
        )
    if manifest.get("artifact") != snapshot_path.name:
        raise DeviceCollectionError(
            f"integrity check failed: manifest does not identify {snapshot_path.name}"
        )
    if manifest.get("size") != actual_size:
        raise DeviceCollectionError(
            f"integrity check failed: size mismatch for {snapshot_path}"
        )
    if manifest.get("sha256") != actual_digest:
        raise DeviceCollectionError(
            f"integrity check failed: SHA-256 mismatch for {snapshot_path}"
        )
    return {
        "snapshot": str(snapshot_path),
        "manifest": str(manifest_path),
        "sha256": actual_digest,
        "size": actual_size,
        "verified": True,
    }


def snapshot(
    investigation: str | Path,
    *,
    runner: Runner = _run,
    which: Callable[[str], str | None] = shutil.which,
    now: Callable[[], datetime] | None = None,
) -> Path:
    """Collect a redacted device/app snapshot into an investigation workspace."""
    executable = _find_tool(which)
    if executable is None:
        raise DeviceCollectionError("pymobiledevice3 is not installed")

    workspace = Path(investigation).expanduser().resolve()
    if not workspace.is_dir():
        raise DeviceCollectionError(f"investigation does not exist: {workspace}")

    timestamp = (now or (lambda: datetime.now(UTC)))().astimezone(UTC)
    stamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = workspace / "device"
    snapshot_path = evidence_dir / f"ios-snapshot-{stamp}.json"
    manifest_path = evidence_dir / f"ios-snapshot-{stamp}.manifest.json"
    conflicts = [path for path in (snapshot_path, manifest_path) if path.exists()]
    if conflicts:
        raise DeviceCollectionError(
            f"refusing to overwrite existing evidence: {conflicts[0]}"
        )

    device = _json_output(
        runner([executable, "lockdown", "info"]),
        "device query",
    )
    apps = _json_output(runner([executable, "apps", "list"]), "application query")

    evidence_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "collected_at": timestamp.isoformat().replace("+00:00", "Z"),
        "collection_mode": "read-only",
        "collector": TOOL,
        "collector_host": {
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "device": redact(device),
        "applications": _normalize_apps(apps),
        "assessment": {
            "standard_configuration": "not_assessed",
            "jailbreak_status": "not_assessed",
        },
    }
    _write_json(snapshot_path, payload)

    try:
        _write_json(
            manifest_path,
            {
                "schema_version": SCHEMA_VERSION,
                "artifact": snapshot_path.name,
                "sha256": _sha256(snapshot_path),
                "size": snapshot_path.stat().st_size,
            },
        )
    except OSError:
        snapshot_path.unlink(missing_ok=True)
        raise
    return snapshot_path


def _bundle_id(app: dict[str, Any]) -> str:
    return str(
        app.get("bundle_id")
        or app.get("CFBundleIdentifier")
        or app.get("BundleIdentifier")
        or ""
    )


def _validate_snapshot(payload: Any, path: Path) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DeviceCollectionError(f"invalid snapshot {path}: root must be an object")
    if not isinstance(payload.get("device"), dict):
        raise DeviceCollectionError(
            f"invalid snapshot {path}: device must be an object"
        )
    applications = payload.get("applications")
    if not isinstance(applications, list) or not all(
        isinstance(app, dict) for app in applications
    ):
        raise DeviceCollectionError(
            f"invalid snapshot {path}: applications must be a list of objects"
        )
    return payload


def compare_snapshots(before: str | Path, after: str | Path) -> dict[str, Any]:
    """Compare two Astranyx iOS snapshots without contacting a device."""
    before_path, after_path = Path(before), Path(after)
    for snapshot_path in (before_path, after_path):
        if _manifest_path(snapshot_path).exists():
            verify_snapshot(snapshot_path)
    try:
        old = _validate_snapshot(
            json.loads(before_path.read_text(encoding="utf-8")), before_path
        )
        new = _validate_snapshot(
            json.loads(after_path.read_text(encoding="utf-8")), after_path
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise DeviceCollectionError(f"unable to read snapshots: {exc}") from exc

    old_apps = {_bundle_id(app): app for app in old.get("applications", [])}
    new_apps = {_bundle_id(app): app for app in new.get("applications", [])}
    old_apps.pop("", None)
    new_apps.pop("", None)

    changed = [
        {
            "bundle_id": bundle_id,
            "before": old_apps[bundle_id],
            "after": new_apps[bundle_id],
        }
        for bundle_id in sorted(old_apps.keys() & new_apps.keys())
        if old_apps[bundle_id] != new_apps[bundle_id]
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "before": str(before_path),
        "after": str(after_path),
        "device_changed": old.get("device") != new.get("device"),
        "applications_added": [
            new_apps[key] for key in sorted(new_apps.keys() - old_apps.keys())
        ],
        "applications_removed": [
            old_apps[key] for key in sorted(old_apps.keys() - new_apps.keys())
        ],
        "applications_changed": changed,
    }
