"""Defensive importer for MobSF static-analysis JSON reports."""

from __future__ import annotations

import hashlib
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


def _plain_text(value: Any) -> str:
    """Normalize user labels while preserving characters for output escaping."""
    return re.sub(r"\s+", " ", str(value)).strip()[:MAX_TEXT]


def _severity(value: Any) -> str | None:
    return SEVERITIES.get(_text(value).casefold())


def _derived_rule_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_text(value).casefold().encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


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
    if isinstance(section.get("findings"), dict):
        section = section["findings"]
    for rule_id, entry in section.items():
        if not isinstance(entry, dict):
            continue
        files = entry.get("files")
        if isinstance(files, dict) and files:
            for file, detail in files.items():
                detail_data = detail if isinstance(detail, dict) else {}
                metadata = entry.get("metadata")
                metadata = metadata if isinstance(metadata, dict) else {}
                finding = _finding(
                    rule_id=str(rule_id),
                    entry=entry,
                    file=file,
                    evidence=detail_data.get("match_string")
                    or detail_data.get("match_lines")
                    or metadata.get("description"),
                    line=detail_data.get("lines") or detail,
                )
                if finding:
                    findings.append(finding)
        else:
            finding = _finding(rule_id=str(rule_id), entry=entry)
            if finding:
                findings.append(finding)
    return findings


def _named_list_findings(
    section: Any, list_key: str, source_name: str
) -> list[Finding]:
    if not isinstance(section, dict) or not isinstance(section.get(list_key), list):
        return []
    findings = []
    for index, entry in enumerate(section[list_key]):
        if not isinstance(entry, dict):
            continue
        description = entry.get("description") or index
        finding = _finding(
            rule_id=_derived_rule_id(source_name, description),
            entry=entry,
            file=source_name,
            evidence=entry.get("scope") or entry.get("description"),
        )
        if finding:
            findings.append(finding)
    return findings


def _certificate_findings(section: Any) -> list[Finding]:
    if not isinstance(section, dict):
        return []
    entries = section.get("certificate_findings")
    if not isinstance(entries, list):
        return []
    findings = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, (list, tuple)) or len(entry) < 3:
            continue
        severity, description, title = entry[:3]
        finding = _finding(
            rule_id=_derived_rule_id("certificate", title or index),
            entry={
                "severity": severity,
                "description": description,
                "title": title,
            },
            file="signing-certificate",
            evidence=title,
        )
        if finding:
            findings.append(finding)
    return findings


def _android_binary_findings(section: Any) -> list[Finding]:
    if not isinstance(section, list):
        return []
    findings = []
    for binary in section:
        if not isinstance(binary, dict):
            continue
        name = binary.get("name") or "native-binary"
        for check, entry in binary.items():
            if check == "name" or not isinstance(entry, dict):
                continue
            finding = _finding(
                rule_id=f"binary_{check}",
                entry=entry,
                file=name,
                evidence=entry.get("description"),
            )
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
    findings.extend(
        _named_list_findings(
            payload.get("network_security"), "network_findings", "network"
        )
    )
    findings.extend(_certificate_findings(payload.get("certificate_analysis")))
    binary = payload.get("binary_analysis")
    findings.extend(
        _code_findings(binary)
        if isinstance(binary, dict)
        else _android_binary_findings(binary)
    )
    findings = list({finding.fingerprint: finding for finding in findings}.values())
    findings.sort(key=lambda item: (item.fingerprint, item.file, item.line))
    metadata = {
        "source": "mobsf",
        "app_name": _text(payload.get("app_name")),
        "package_name": _text(payload.get("package_name")),
        "scan_type": _text(payload.get("scan_type") or payload.get("app_type")),
        "normalized_findings": len(findings),
        "imported_sections": sorted(
            section
            for section in (
                "binary_analysis",
                "certificate_analysis",
                "code_analysis",
                "manifest_analysis",
                "network_security",
            )
            if section in payload
        ),
        "unsupported_sections": sorted(
            section
            for section in ("permissions", "secrets", "trackers")
            if section in payload
        ),
    }
    return metadata, findings


def import_report(
    path: str | Path,
    output: str | Path,
    *,
    client: str = "",
    consultant: str = "",
    assessment_title: str = "",
) -> dict[str, Any]:
    """Import MobSF JSON and render normalized Astranyx artifacts."""
    metadata, findings = load(path)
    metadata.update(
        {
            key: _plain_text(value)
            for key, value in {
                "client": client,
                "consultant": consultant,
                "assessment_title": assessment_title,
            }.items()
            if value
        }
    )
    output_path = Path(output)
    artifact_names = (
        "app.js",
        "findings.csv",
        "findings.json",
        "findings.sarif",
        "index.html",
        "manifest.json",
        "style.css",
    )
    try:
        output_path.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise MobSFImportError(
            f"refusing to overwrite existing output directory: {output_path}"
        ) from exc
    report = Report(
        metadata["package_name"] or metadata["app_name"] or str(path),
        findings,
        metadata=metadata,
    )
    try:
        render(report, output_path)
        export_sarif(report, output_path)
        artifacts = []
        for name in artifact_names:
            artifact = output_path / name
            if name == "manifest.json" or not artifact.is_file():
                continue
            content = artifact.read_bytes()
            artifacts.append(
                {
                    "path": name,
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        with (output_path / "manifest.json").open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps({"schema_version": 1, "artifacts": artifacts}, indent=2)
                + "\n"
            )
    except Exception:
        for name in artifact_names:
            (output_path / name).unlink(missing_ok=True)
        output_path.rmdir()
        raise
    return {
        **metadata,
        "findings_imported": len(findings),
        "output_directory": str(output_path),
    }
