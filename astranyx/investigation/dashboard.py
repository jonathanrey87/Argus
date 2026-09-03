"""Offline HTML dashboard for a sealed Astranyx investigation."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

TEMPLATE = Path(__file__).parent / "templates" / "dashboard.html"


def _text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value)


def _module_cards(
    selected_modules: list[str], module_results: dict, failures: list[dict]
) -> str:
    failed = {
        item.get("module")
        for item in failures
        if isinstance(item, dict) and isinstance(item.get("module"), str)
    }
    cards = []
    for module in selected_modules:
        if module in module_results:
            status = "completed"
        elif module in failed:
            status = "failed"
        else:
            status = "pending"
        cards.append(
            '<div class="module-card">'
            f"<strong>{html.escape(module.title())}</strong>"
            f'<span class="status {status}">{status}</span>'
            "</div>"
        )
    return "".join(cards) or '<p class="empty">No analyzers selected.</p>'


def _finding_rows(findings: list[dict]) -> str:
    rows = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = _text(finding.get("severity"), "Info")
        band = (
            severity.casefold()
            if severity.casefold()
            in {
                "critical",
                "high",
                "medium",
                "low",
                "info",
            }
            else "info"
        )
        modules = finding.get("modules", [])
        module_names = (
            ", ".join(item for item in modules if isinstance(item, str))
            if isinstance(modules, list)
            else ""
        )
        searchable = " ".join(
            _text(finding.get(key))
            for key in ("fingerprint", "category", "file", "evidence")
        )
        rows.append(
            f'<tr class="finding" data-severity="{band}" '
            f'data-search="{html.escape(searchable.casefold(), quote=True)}">'
            f'<td><span class="severity {band}">{html.escape(severity)}</span></td>'
            f"<td>{html.escape(_text(finding.get('category'), 'Uncategorized'))}</td>"
            f'<td class="mono">{html.escape(_text(finding.get("file"), "n/a"))}</td>'
            f"<td>{html.escape(module_names or 'n/a')}</td>"
            f"<td>{html.escape(_text(finding.get('confidence'), 'n/a'))}</td>"
            f"<td>{html.escape(_text(finding.get('cvss_score'), 'not assessed'))}</td>"
            "<td><details><summary>View</summary>"
            f'<p class="mono">{html.escape(_text(finding.get("fingerprint"), "Unfingerprinted"))}</p>'
            f"<pre>{html.escape(_text(finding.get('evidence'), 'No evidence supplied.'))}</pre>"
            "</details></td></tr>"
        )
    return "".join(rows) or (
        '<tr id="no-findings"><td colspan="7" class="empty">'
        "No normalized findings are currently available.</td></tr>"
    )


def render(
    workspace: Path,
    metadata: dict,
    module_results: dict,
    failures: list[dict],
    deduplicated: dict,
    graph: dict,
) -> Path:
    """Render a self-contained dashboard from checkpoint data."""
    findings = deduplicated.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    severities = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = _text(finding.get("severity"), "info").casefold()
        severities[severity if severity in severities else "info"] += 1

    selected = metadata.get("selected_modules", [])
    if not isinstance(selected, list):
        selected = []
    summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
    replacements = {
        "{{INVESTIGATION_ID}}": html.escape(_text(metadata.get("id"), "Unknown")),
        "{{TARGET}}": html.escape(_text(metadata.get("target"), "Not recorded")),
        "{{STATUS}}": html.escape(_text(metadata.get("status"), "unknown")),
        "{{CREATED}}": html.escape(_text(metadata.get("created"), "Unknown")),
        "{{COMPLETED}}": html.escape(_text(metadata.get("completed"), "In progress")),
        "{{PROFILE}}": html.escape(_text(metadata.get("profile"), "Unknown")),
        "{{TOTAL}}": str(len(findings)),
        "{{CRITICAL}}": str(severities["critical"]),
        "{{HIGH}}": str(severities["high"]),
        "{{MEDIUM}}": str(severities["medium"]),
        "{{LOW}}": str(severities["low"]),
        "{{INFO}}": str(severities["info"]),
        "{{GRAPH_NODES}}": html.escape(_text(summary.get("nodes"), "0")),
        "{{GRAPH_EDGES}}": html.escape(_text(summary.get("edges"), "0")),
        "{{DUPLICATES}}": html.escape(
            _text(deduplicated.get("duplicates_removed"), "0")
        ),
        "{{COLLISIONS}}": html.escape(
            _text(len(deduplicated.get("fingerprint_collisions", [])), "0")
        ),
        "{{MODULE_CARDS}}": _module_cards(selected, module_results, failures),
        "{{FINDING_ROWS}}": _finding_rows(findings),
    }
    page = TEMPLATE.read_text(encoding="utf-8")
    for placeholder, value in replacements.items():
        page = page.replace(placeholder, value)

    output = workspace / "html" / "index.html"
    output.write_text(page, encoding="utf-8")
    return output
