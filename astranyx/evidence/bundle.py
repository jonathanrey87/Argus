"""Local-only evidence capture with redaction, sealing, and retest comparison."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_SOURCE_BYTES = 10_485_760
MAX_BUNDLE_BYTES = 52_428_800
MAX_PLAN_BYTES = 10_485_760
SECRET_PATTERN = re.compile(
    r"(?im)(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+"
    r"|([\"']?(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|access[_-]?key)[\"']?\s*[:=]\s*)"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;&]+)'
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


class EvidenceError(RuntimeError):
    """Raised when evidence cannot be captured or verified safely."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _redact_url(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        query = urlencode(
            [
                (key, "[REDACTED]")
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        return urlunsplit((parsed.scheme, host, parsed.path, query, ""))
    except ValueError:
        return "[REDACTED-URL]"


def redact_text(value: str) -> tuple[str, int]:
    count = 0

    def secret(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        if match.group(1):
            return f"{match.group(1)}: [REDACTED]"
        return f"{match.group(2)}[REDACTED]"

    redacted = SECRET_PATTERN.sub(secret, value)
    for match in list(URL_PATTERN.finditer(redacted)):
        parsed = urlsplit(match.group(0))
        if parsed.username is not None or parsed.password is not None:
            count += 1
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        count += sum(item != "[REDACTED]" for _, item in query_items)
    return URL_PATTERN.sub(_redact_url, redacted), count


def _load_plan(path: str | Path, plan_id: str | None) -> tuple[dict[str, Any], str]:
    source = Path(path).expanduser()
    try:
        if source.stat().st_size > MAX_PLAN_BYTES:
            raise EvidenceError("validation plan exceeds 10 MiB")
        document = json.loads(source.read_text(encoding="utf-8"))
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"unable to load validation plan: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise EvidenceError("unsupported validation-plan document")
    plans = document.get("plans")
    if not isinstance(plans, list) or not all(isinstance(item, dict) for item in plans):
        raise EvidenceError("validation-plan document requires plans")
    selected = [item for item in plans if plan_id is None or item.get("id") == plan_id]
    if len(selected) != 1:
        raise EvidenceError("select exactly one validation plan with --plan-id")
    plan = selected[0]
    if plan.get("execution_allowed") is not False or plan.get("status") != "planned":
        raise EvidenceError(
            "evidence capture requires a non-executing planned validation"
        )
    if not isinstance(plan.get("id"), str) or not plan["id"].startswith("vp-"):
        raise EvidenceError("validation plan has an invalid ID")
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    return plan, _sha256(canonical)


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceError("evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def capture_bundle(
    plan_path: str | Path,
    sources: list[str | Path],
    output: str | Path,
    *,
    plan_id: str | None = None,
) -> dict[str, Any]:
    """Copy UTF-8 local evidence into a new redacted and sealed bundle."""
    if not sources:
        raise EvidenceError("at least one local evidence source is required")
    plan, plan_sha256 = _load_plan(plan_path, plan_id)
    output_path = Path(output).expanduser()
    try:
        output_path.mkdir(parents=True, exist_ok=False)
        os.chmod(output_path, 0o700)
        evidence_dir = output_path / "evidence"
        evidence_dir.mkdir(mode=0o700)
        artifacts = []
        total = 0
        seen: set[Path] = set()
        for index, value in enumerate(sources, start=1):
            source = Path(value).expanduser()
            if source.is_symlink() or not source.is_file():
                raise EvidenceError(
                    f"evidence source must be a regular non-symlink file: {source}"
                )
            resolved = source.resolve()
            if resolved in seen:
                raise EvidenceError("duplicate evidence source")
            seen.add(resolved)
            size = source.stat().st_size
            if size > MAX_SOURCE_BYTES or total + size > MAX_BUNDLE_BYTES:
                raise EvidenceError("evidence source or bundle exceeds size limit")
            raw = source.read_bytes()
            if len(raw) > MAX_SOURCE_BYTES or total + len(raw) > MAX_BUNDLE_BYTES:
                raise EvidenceError("evidence source changed beyond the size limit")
            total += len(raw)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise EvidenceError(
                    "only UTF-8 text evidence can be safely redacted"
                ) from exc
            redacted, redactions = redact_text(text)
            encoded = redacted.encode("utf-8")
            logical_name = f"artifact-{index:04d}.txt"
            relative = f"evidence/{logical_name}"
            _write_exclusive(evidence_dir / logical_name, encoded)
            artifacts.append(
                {
                    "id": f"ev-{_sha256((plan['id'] + ':' + str(index)).encode())[:20]}",
                    "path": relative,
                    "media_type": "text/plain; charset=utf-8",
                    "source_name": source.name,
                    "source_size_bytes": len(raw),
                    "source_sha256": _sha256(raw),
                    "redacted_size_bytes": len(encoded),
                    "redacted_sha256": _sha256(encoded),
                    "redactions": redactions,
                }
            )
        index_document = {
            "schema_version": 1,
            "plan_id": plan["id"],
            "plan_sha256": plan_sha256,
            "captured_at": datetime.now(UTC).isoformat(),
            "artifacts": artifacts,
        }
        index_bytes = (
            json.dumps(index_document, indent=2, sort_keys=True) + "\n"
        ).encode()
        _write_exclusive(output_path / "index.json", index_bytes)
        manifest = {
            "schema_version": 1,
            "plan_id": plan["id"],
            "plan_sha256": plan_sha256,
            "artifacts": [
                {
                    "path": item["path"],
                    "size_bytes": item["redacted_size_bytes"],
                    "sha256": item["redacted_sha256"],
                }
                for item in artifacts
            ]
            + [
                {
                    "path": "index.json",
                    "size_bytes": len(index_bytes),
                    "sha256": _sha256(index_bytes),
                }
            ],
        }
        manifest_bytes = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()
        _write_exclusive(output_path / "manifest.json", manifest_bytes)
        _write_exclusive(
            output_path / "seal.json",
            (
                json.dumps(
                    {"schema_version": 1, "manifest_sha256": _sha256(manifest_bytes)},
                    indent=2,
                )
                + "\n"
            ).encode(),
        )
        return {
            "output": str(output_path),
            "plan_id": plan["id"],
            "artifacts": len(artifacts),
            "redactions": sum(item["redactions"] for item in artifacts),
        }
    except Exception:
        if output_path.exists():
            for child in sorted(output_path.rglob("*"), reverse=True):
                if child.is_file() and not child.is_symlink():
                    child.unlink()
                elif child.is_dir() and not child.is_symlink():
                    child.rmdir()
            output_path.rmdir()
        raise


def _safe_child(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise EvidenceError("unsafe evidence artifact path")
    unresolved = root / value
    if unresolved.is_symlink():
        raise EvidenceError("evidence artifacts must not be symbolic links")
    candidate = unresolved.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise EvidenceError("unsafe evidence artifact path") from exc
    return candidate


def verify_bundle(bundle: str | Path) -> dict[str, Any]:
    root = Path(bundle).expanduser().resolve()
    try:
        if (root / "manifest.json").stat().st_size > MAX_PLAN_BYTES:
            raise EvidenceError("evidence manifest exceeds 10 MiB")
        if (root / "seal.json").stat().st_size > MAX_PLAN_BYTES:
            raise EvidenceError("evidence seal exceeds 10 MiB")
        manifest_bytes = (root / "manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        seal = json.loads((root / "seal.json").read_text(encoding="utf-8"))
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"unable to read evidence bundle: {exc}") from exc
    failures = []
    if manifest.get("schema_version") != 1 or seal.get("schema_version") != 1:
        raise EvidenceError("unsupported evidence bundle schema")
    if seal.get("manifest_sha256") != _sha256(manifest_bytes):
        failures.append({"path": "manifest.json", "reason": "seal mismatch"})
    records = manifest.get("artifacts")
    if not isinstance(records, list):
        raise EvidenceError("invalid evidence manifest")
    index_records = [
        record
        for record in records
        if isinstance(record, dict) and record.get("path") == "index.json"
    ]
    if len(index_records) != 1:
        raise EvidenceError("evidence manifest must contain exactly one index")
    seen = set()
    total_checked_bytes = 0
    for record in records:
        if not isinstance(record, dict):
            raise EvidenceError("invalid evidence artifact record")
        artifact = _safe_child(root, record.get("path"))
        relative = artifact.relative_to(root).as_posix()
        if relative in seen:
            failures.append({"path": relative, "reason": "duplicate path"})
            continue
        seen.add(relative)
        try:
            actual_size = artifact.stat().st_size
            per_file_limit = (
                MAX_PLAN_BYTES if relative == "index.json" else MAX_SOURCE_BYTES
            )
            if (
                actual_size > per_file_limit
                or total_checked_bytes + actual_size > MAX_BUNDLE_BYTES
            ):
                failures.append({"path": relative, "reason": "size limit exceeded"})
                continue
            total_checked_bytes += actual_size
            content = artifact.read_bytes()
        except OSError:
            failures.append({"path": relative, "reason": "unreadable"})
            continue
        if len(content) != record.get("size_bytes"):
            failures.append({"path": relative, "reason": "size mismatch"})
        if _sha256(content) != record.get("sha256"):
            failures.append({"path": relative, "reason": "SHA-256 mismatch"})
    try:
        if (root / "index.json").stat().st_size > MAX_PLAN_BYTES:
            raise EvidenceError("evidence index exceeds 10 MiB")
        index_document = json.loads((root / "index.json").read_text(encoding="utf-8"))
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"unable to read evidence index: {exc}") from exc
    if index_document.get("plan_id") != manifest.get("plan_id") or index_document.get(
        "plan_sha256"
    ) != manifest.get("plan_sha256"):
        failures.append({"path": "index.json", "reason": "plan binding mismatch"})
    return {
        "bundle": str(root),
        "plan_id": manifest.get("plan_id"),
        "plan_sha256": manifest.get("plan_sha256"),
        "manifest_sha256": _sha256(manifest_bytes),
        "artifacts_checked": len(seen),
        "valid": not failures,
        "failures": failures,
    }


def compare_bundles(baseline: str | Path, current: str | Path) -> dict[str, Any]:
    before = verify_bundle(baseline)
    after = verify_bundle(current)
    if not before["valid"] or not after["valid"]:
        raise EvidenceError("cannot compare an invalid evidence bundle")
    if before["plan_id"] != after["plan_id"]:
        raise EvidenceError("evidence bundles belong to different validation plans")

    def indexes(root_value: str | Path) -> dict[str, dict[str, Any]]:
        document = json.loads(
            (Path(root_value).expanduser().resolve() / "index.json").read_text()
        )
        return {item["source_name"]: item for item in document["artifacts"]}

    old, new = indexes(baseline), indexes(current)
    shared = old.keys() & new.keys()
    changed = sorted(
        key
        for key in shared
        if old[key]["redacted_sha256"] != new[key]["redacted_sha256"]
    )
    unchanged = sorted(shared - set(changed))
    return {
        "schema_version": 1,
        "plan_id": before["plan_id"],
        "summary": {
            "added": len(new.keys() - old.keys()),
            "removed": len(old.keys() - new.keys()),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()),
        "changed": changed,
        "unchanged": unchanged,
    }
