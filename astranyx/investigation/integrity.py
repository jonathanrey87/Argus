"""Integrity verification for sealed Astranyx investigations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class IntegrityError(RuntimeError):
    """Raised when an investigation manifest cannot be evaluated."""


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"unable to read investigation manifest: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        raise IntegrityError("invalid investigation manifest: artifacts must be a list")
    return payload


def _safe_artifact(root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def verify(workspace: str | Path) -> dict[str, Any]:
    """Verify every artifact recorded in an investigation manifest."""
    root = Path(workspace).expanduser().resolve()
    manifest = _load_manifest(root / "manifest.json")
    failures: list[dict[str, Any]] = []
    checked = 0
    seen: set[str] = set()

    for index, record in enumerate(manifest["artifacts"]):
        if not isinstance(record, dict):
            failures.append({"index": index, "reason": "invalid artifact record"})
            continue

        relative = record.get("path")
        artifact = _safe_artifact(root, relative)
        if artifact is None:
            failures.append(
                {"index": index, "path": relative, "reason": "unsafe artifact path"}
            )
            continue
        normalized = artifact.relative_to(root).as_posix()
        if normalized in seen:
            failures.append(
                {"index": index, "path": relative, "reason": "duplicate artifact path"}
            )
            continue
        seen.add(normalized)

        try:
            content = artifact.read_bytes()
        except OSError as exc:
            failures.append(
                {"index": index, "path": relative, "reason": f"unreadable: {exc}"}
            )
            continue

        checked += 1
        actual_size = len(content)
        actual_digest = hashlib.sha256(content).hexdigest()
        if record.get("size_bytes") != actual_size:
            failures.append(
                {
                    "index": index,
                    "path": relative,
                    "reason": "size mismatch",
                    "expected": record.get("size_bytes"),
                    "actual": actual_size,
                }
            )
        if record.get("sha256") != actual_digest:
            failures.append(
                {
                    "index": index,
                    "path": relative,
                    "reason": "SHA-256 mismatch",
                    "expected": record.get("sha256"),
                    "actual": actual_digest,
                }
            )

    investigation = manifest.get("investigation")
    investigation_id = (
        investigation.get("id") if isinstance(investigation, dict) else None
    )
    return {
        "workspace": str(root),
        "investigation_id": investigation_id,
        "artifacts_recorded": len(manifest["artifacts"]),
        "artifacts_checked": checked,
        "valid": not failures,
        "failures": failures,
    }
