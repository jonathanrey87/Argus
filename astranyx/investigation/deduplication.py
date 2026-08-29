"""Conservative cross-module deduplication for normalized findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _identity(finding: dict[str, Any]) -> tuple[Any, ...]:
    """Return fields that must agree before a fingerprint may be merged."""
    return (
        finding.get("category"),
        finding.get("rule_id", ""),
        finding.get("file"),
        finding.get("evidence"),
    )


def _preferred(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Choose the richest, highest-severity observation as the canonical one."""

    def confidence(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    left_key = (
        SEVERITY_RANK.get(str(left.get("severity", "")).casefold(), 0),
        confidence(left.get("confidence")),
        len(str(left.get("reason", ""))),
        len(str(left.get("note", ""))),
    )
    right_key = (
        SEVERITY_RANK.get(str(right.get("severity", "")).casefold(), 0),
        confidence(right.get("confidence")),
        len(str(right.get("reason", ""))),
        len(str(right.get("note", ""))),
    )
    return right if right_key > left_key else left


def deduplicate(module_findings: dict[str, list[dict]]) -> dict[str, Any]:
    """Merge matching fingerprints across modules without hiding collisions."""
    groups: dict[tuple[str, tuple[Any, ...]], dict[str, Any]] = {}
    ungrouped: list[dict[str, Any]] = []
    observations = 0
    collisions: set[str] = set()
    identities_by_fingerprint: dict[str, set[tuple[Any, ...]]] = {}

    for module in sorted(module_findings):
        for finding in module_findings[module]:
            observations += 1
            fingerprint = finding.get("fingerprint")
            if not isinstance(fingerprint, str) or not fingerprint.startswith("asx-"):
                preserved = dict(finding)
                preserved["modules"] = [module]
                preserved["observations"] = 1
                preserved["fingerprint_collision"] = False
                ungrouped.append(preserved)
                continue
            identity = _identity(finding)
            identities = identities_by_fingerprint.setdefault(fingerprint, set())
            identities.add(identity)
            if len(identities) > 1:
                collisions.add(fingerprint)

            key = (fingerprint, identity)
            if key not in groups:
                groups[key] = {
                    "finding": dict(finding),
                    "modules": [module],
                    "observations": 1,
                }
                continue

            group = groups[key]
            group["finding"] = _preferred(group["finding"], finding)
            group["observations"] += 1
            if module not in group["modules"]:
                group["modules"].append(module)

    findings = list(ungrouped)
    ordered_groups = sorted(
        groups.items(), key=lambda item: (item[0][0], repr(item[0][1]))
    )
    for (fingerprint, _identity_value), group in ordered_groups:
        finding = group["finding"]
        finding["fingerprint"] = fingerprint
        finding["modules"] = group["modules"]
        finding["observations"] = group["observations"]
        finding["fingerprint_collision"] = fingerprint in collisions
        findings.append(finding)

    return {
        "schema_version": 1,
        "observations": observations,
        "unique_findings": len(findings),
        "duplicates_removed": observations - len(findings),
        "fingerprint_collisions": sorted(collisions),
        "findings": findings,
    }


def load_module_findings(module_results: dict[str, dict]) -> dict[str, list[dict]]:
    """Load normalized finding reports advertised by completed modules."""
    loaded: dict[str, list[dict]] = {}
    for module, result in module_results.items():
        report_path = result.get("finding_report")
        if not report_path:
            continue
        path = Path(report_path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        findings = payload.get("findings") if isinstance(payload, dict) else None
        if isinstance(findings, list):
            loaded[module] = [item for item in findings if isinstance(item, dict)]
    return loaded


def write(workspace: Path, module_results: dict[str, dict]) -> tuple[Path, dict]:
    """Write the current investigation-wide normalized findings artifact."""
    result = deduplicate(load_module_findings(module_results))
    output = workspace / "analysis" / "findings.json"
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return output, result
