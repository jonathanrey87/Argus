"""Baseline and retest comparison for normalized Astranyx findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 50 * 1024 * 1024
SUPPORTED_SCHEMA_VERSION = 1
SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class RetestError(RuntimeError):
    """Raised when assessment reports cannot be compared safely."""


def _load(path: str | Path) -> tuple[Path, dict[str, Any]]:
    report_path = Path(path)
    try:
        if report_path.stat().st_size > MAX_REPORT_BYTES:
            raise RetestError(
                f"report exceeds {MAX_REPORT_BYTES} byte safety limit: {report_path}"
            )
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except RetestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RetestError(f"unable to read report {report_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise RetestError(f"invalid report {report_path}: root must be an object")
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise RetestError(
            f"unsupported report schema in {report_path}: "
            f"expected {SUPPORTED_SCHEMA_VERSION}"
        )
    findings = payload.get("findings")
    if not isinstance(findings, list) or not all(
        isinstance(item, dict) for item in findings
    ):
        raise RetestError(f"invalid report {report_path}: findings must be objects")

    fingerprints: set[str] = set()
    for item in findings:
        fingerprint = item.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint.startswith("asx-"):
            raise RetestError(f"invalid finding fingerprint in {report_path}")
        if fingerprint in fingerprints:
            raise RetestError(f"duplicate finding fingerprint in {report_path}")
        fingerprints.add(fingerprint)
    return report_path, payload


def _identity(finding: dict[str, Any]) -> tuple[str, str, str]:
    rule = str(finding.get("rule_id") or finding.get("category") or "").casefold()
    source = str(finding.get("source") or "astranyx").casefold()
    file = str(finding.get("file") or "").replace("\\", "/").casefold()
    return source, rule, file


def _regressed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    old_severity = SEVERITY_RANK.get(str(before.get("severity")), -1)
    new_severity = SEVERITY_RANK.get(str(after.get("severity")), -1)
    old_confidence = before.get("confidence", 0)
    new_confidence = after.get("confidence", 0)
    return new_severity > old_severity or (
        new_severity == old_severity
        and isinstance(old_confidence, int)
        and isinstance(new_confidence, int)
        and new_confidence > old_confidence
    )


def _change(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    fields = {}
    for name in ("severity", "confidence", "evidence", "reason"):
        if before.get(name) != after.get(name):
            fields[name] = {"before": before.get(name), "after": after.get(name)}
    return {"before": before, "after": after, "changes": fields}


def compare(baseline: str | Path, current: str | Path) -> dict[str, Any]:
    """Classify findings between a baseline assessment and its retest."""
    baseline_path, old_report = _load(baseline)
    current_path, new_report = _load(current)
    old = {item["fingerprint"]: item for item in old_report["findings"]}
    new = {item["fingerprint"]: item for item in new_report["findings"]}

    shared_keys = old.keys() & new.keys()
    persistent = []
    changed = []
    regressions = []
    for key in sorted(shared_keys):
        change = _change(old[key], new[key])
        if not change["changes"]:
            persistent.append(new[key])
        elif _regressed(old[key], new[key]):
            regressions.append(change)
        else:
            changed.append(change)
    unmatched_old = [old[key] for key in sorted(old.keys() - shared_keys)]
    unmatched_new = [new[key] for key in sorted(new.keys() - shared_keys)]

    old_by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    new_by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for finding in unmatched_old:
        old_by_identity.setdefault(_identity(finding), []).append(finding)
    for finding in unmatched_new:
        new_by_identity.setdefault(_identity(finding), []).append(finding)

    matched_old: set[str] = set()
    matched_new: set[str] = set()
    for identity in sorted(old_by_identity.keys() & new_by_identity.keys()):
        old_candidates = old_by_identity[identity]
        new_candidates = new_by_identity[identity]
        if len(old_candidates) != 1 or len(new_candidates) != 1:
            continue
        before, after = old_candidates[0], new_candidates[0]
        change = _change(before, after)
        matched_old.add(before["fingerprint"])
        matched_new.add(after["fingerprint"])
        if _regressed(before, after):
            regressions.append(change)
        else:
            changed.append(change)

    fixed = [item for item in unmatched_old if item["fingerprint"] not in matched_old]
    added = [item for item in unmatched_new if item["fingerprint"] not in matched_new]
    summary = {
        "baseline_total": len(old),
        "current_total": len(new),
        "new": len(added),
        "fixed": len(fixed),
        "persistent": len(persistent),
        "changed": len(changed),
        "regressed": len(regressions),
    }
    return {
        "schema_version": 1,
        "comparison_type": "baseline_retest",
        "baseline": str(baseline_path),
        "current": str(current_path),
        "summary": summary,
        "new": added,
        "fixed": fixed,
        "persistent": persistent,
        "changed": changed,
        "regressed": regressions,
    }


def _markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Astranyx Retest Summary",
        "",
        f"- Baseline findings: {summary['baseline_total']}",
        f"- Current findings: {summary['current_total']}",
        f"- Fixed: {summary['fixed']}",
        f"- New: {summary['new']}",
        f"- Persistent: {summary['persistent']}",
        f"- Changed: {summary['changed']}",
        f"- Regressed: {summary['regressed']}",
    ]
    for section in ("regressed", "new", "fixed", "persistent", "changed"):
        lines.extend(("", f"## {section.title()}", ""))
        entries = result[section]
        if not entries:
            lines.append("None.")
            continue
        for entry in entries:
            finding = entry.get("after", entry) if isinstance(entry, dict) else entry
            severity = _markdown_text(finding.get("severity", "Unknown"))
            category = _markdown_text(finding.get("category", "Finding"))
            file = _markdown_text(finding.get("file", "application"))
            line = finding.get("line", 1)
            lines.append(f"- **{severity}** {category} — `{file}:{line}`")
    return "\n".join(lines) + "\n"


def _markdown_text(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")[:1_000]
    )


def _write_exclusive(path: Path, content: str) -> None:
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content)
    except FileExistsError as exc:
        raise RetestError(f"refusing to overwrite existing output: {path}") from exc


def write_report(
    baseline: str | Path, current: str | Path, output: str | Path
) -> dict[str, Any]:
    """Write a sealed JSON and Markdown retest bundle."""
    result = compare(baseline, current)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / "retest.json"
    markdown_path = output_path / "retest.md"
    manifest_path = output_path / "manifest.json"
    paths = (json_path, markdown_path, manifest_path)
    if any(path.exists() for path in paths):
        conflict = next(path for path in paths if path.exists())
        raise RetestError(f"refusing to overwrite existing output: {conflict}")

    rendered_json = json.dumps(result, indent=2, sort_keys=True) + "\n"
    _write_exclusive(json_path, rendered_json)
    try:
        _write_exclusive(markdown_path, _markdown(result))
        artifacts = []
        for path in (json_path, markdown_path):
            content = path.read_bytes()
            artifacts.append(
                {
                    "path": path.name,
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        _write_exclusive(
            manifest_path,
            json.dumps({"schema_version": 1, "artifacts": artifacts}, indent=2) + "\n",
        )
    except Exception:
        for path in paths:
            path.unlink(missing_ok=True)
        raise
    return {**result["summary"], "output_directory": str(output_path)}
