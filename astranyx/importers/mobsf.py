"""Defensive importer for MobSF static-analysis JSON reports."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path, PurePath
from typing import Any

from astranyx.core.finding import Finding
from astranyx.core.html import render
from astranyx.core.report import Report
from astranyx.core.sarif import export as export_sarif

MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_TEXT = 4_000
SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "error": "High",
    "warning": "Medium",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}


class MobSFImportError(RuntimeError):
    """Raised when a MobSF report cannot be imported safely."""


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, sort_keys=True, ensure_ascii=False)
    else:
        rendered = str(value)
    parser = _TextExtractor()
    try:
        parser.feed(rendered)
        rendered = " ".join(parser.parts)
    except ValueError:
        pass
    return re.sub(r"\s+", " ", rendered).strip()[:MAX_TEXT]


def _severity(value: Any) -> str | None:
    return SEVERITIES.get(_text(value).casefold())


def _line(value: Any) -> int:
    match = re.search(r"\d+", _text(value))
    return max(1, int(match.group())) if match else 1


def _relative_file(value: Any) -> str:
    raw = _text(value).replace("\\", "/")
    parts = [part for part in PurePath(raw).parts if part not in ("/", "..")]
    return "/".join(parts)[:1_000] or "application"


def _finding(
    *,
    rule_id: str,
    entry: dict[str, Any],
    file: Any = "application",
    evidence: Any = "",
    line: Any = 1,
) -> Finding | None:
    metadata = entry.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    severity = _severity(entry.get("severity") or metadata.get("severity"))
    if severity is None:
        return None
    title = _text(
        entry.get("title")
        or entry.get("name")
        or metadata.get("description")
        or rule_id
    )
    description = _text(
        entry.get("description")
        or entry.get("reason")
        or metadata.get("description")
        or title
    )
    normalized_evidence = _text(evidence or entry.get("component") or title)
    return Finding(
        category=title or rule_id,
        severity=severity,
        file=_relative_file(file),
        full_path="",
        line=_line(line),
        evidence=normalized_evidence,
        note=description,
        reason=description,
        confidence=70,
        source="mobsf",
        rule_id=_text(rule_id),
    )


def _code_findings(section: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    for rule_id, entry in section.items():
        if not isinstance(entry, dict):
            continue
        files = entry.get("files")
        if isinstance(files, dict) and files:
            for file, detail in files.items():
                detail = detail if isinstance(detail, dict) else {}
                finding = _finding(
                    rule_id=str(rule_id),
                    entry=entry,
                    file=file,
                    evidence=detail.get("match_string")
                    or detail.get("match_lines")
                    or detail,
                    line=detail.get("lines"),
                )
                if finding:
                    findings.append(finding)
        else:
            finding = _finding(rule_id=str(rule_id), entry=entry)
            if finding:
                findings.append(finding)
    return findings


def _manifest_findings(section: Any) -> list[Finding]:
    if isinstance(section, dict):
        entries = section.get("manifest_findings", section)
        iterable = entries.items() if isinstance(entries, dict) else enumerate(entries)
    elif isinstance(section, list):
        iterable = enumerate(section)
    else:
        return []
    findings = []
    for key, entry in iterable:
        if not isinstance(entry, dict):
            continue
        rule_id = _text(entry.get("rule") or entry.get("rule_id") or key)
        finding = _finding(
            rule_id=rule_id,
            entry=entry,
            file="AndroidManifest.xml",
            evidence=entry.get("component") or entry.get("name"),
        )
        if finding:
            findings.append(finding)
    return findings


def load(path: str | Path) -> tuple[dict[str, Any], list[Finding]]:
    """Load and normalize a bounded MobSF JSON report."""
    report_path = Path(path)
    try:
        size = report_path.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise MobSFImportError(
                f"MobSF report exceeds {MAX_REPORT_BYTES} byte safety limit"
            )
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except MobSFImportError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MobSFImportError(f"unable to read MobSF report: {exc}") from exc
    if not isinstance(payload, dict):
        raise MobSFImportError("invalid MobSF report: root must be an object")
    if "code_analysis" not in payload and "manifest_analysis" not in payload:
        raise MobSFImportError(
            "invalid MobSF report: no code_analysis or manifest_analysis section"
        )
    findings = _code_findings(payload.get("code_analysis"))
    findings.extend(_manifest_findings(payload.get("manifest_analysis")))
    findings = list({finding.fingerprint: finding for finding in findings}.values())
    findings.sort(key=lambda item: (item.fingerprint, item.file, item.line))
    metadata = {
        "source": "mobsf",
        "app_name": _text(payload.get("app_name")),
        "package_name": _text(payload.get("package_name")),
        "scan_type": _text(payload.get("scan_type") or payload.get("app_type")),
        "normalized_findings": len(findings),
    }
    return metadata, findings


def import_report(path: str | Path, output: str | Path) -> dict[str, Any]:
    """Import MobSF JSON and render normalized Astranyx artifacts."""
    metadata, findings = load(path)
    output_path = Path(output)
    report = Report(
        metadata["package_name"] or metadata["app_name"] or str(path), findings
    )
    render(report, output_path)
    export_sarif(report, output_path)
    return {
        **metadata,
        "findings_imported": len(findings),
        "output_directory": str(output_path),
    }
