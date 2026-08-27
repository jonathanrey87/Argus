import csv
import html
import json
import shutil
from pathlib import Path

from astranyx.core.preview import source_preview
from astranyx.intelligence.cwe import get_mapping
from astranyx.intelligence.risk import calculate, rating
from astranyx.intelligence.surface import build_attack_surface

TEMPLATE_DIR = Path(__file__).parent / "templates"
SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def confidence_band(conf):
    if conf >= 80:
        return "high"
    if conf >= 40:
        return "medium"
    return "low"


def confidence_score(findings):
    if not findings:
        return 0

    points = 0
    for f in findings:
        if f.confidence >= 90:
            points += 10
        elif f.confidence >= 70:
            points += 7
        elif f.confidence >= 40:
            points += 4
        else:
            points += 1

    return round((points / (len(findings) * 10)) * 100)


def recommendation(f):
    recs = {
        "Public REST Permission": "Inspect the route callback and verify capability checks or authentication are enforced.",
        "Potential Taint Flow": "Trace the variable from source to sink and confirm whether user input reaches a dangerous operation.",
        "React Dangerous Sink": "Verify HTML is escaped or sanitized before rendering.",
        "DOM Sink": "Check whether user-controlled data reaches innerHTML.",
        "SSRF Sink": "Verify URL validation, allowlists, and blocked internal network destinations.",
        "SQL Query": "Review whether prepare(), whitelisting, or strict validation is used.",
        "Upload Handler": "Verify nonce, capability checks, MIME validation, extension checks, and upload destination.",
        "Deserialization": "Confirm serialized data cannot be attacker-controlled and use allowed_classes=false for unserialize().",
        "Dynamic Include": "Trace include path origin and ensure it cannot be user-controlled.",
    }
    return recs.get(f.category, "Review this code path manually.")


def load_template(name):
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8")


def render_source_preview(finding):
    preview = source_preview(getattr(finding, "full_path", ""), finding.line, radius=5)

    if not preview:
        return "<em>No source preview available.</em>"

    out = ""
    for ln, code in preview:
        cls = "current-line" if ln == finding.line else ""
        out += (
            f'<div class="{cls}">'
            f'<span class="ln">{ln:4}</span> '
            f"{html.escape(code)}"
            "</div>"
        )

    return out


def render_surface_rows(attack_surface):
    rows = ""

    for key, value in attack_surface.items():
        rows += f"<tr><td>{html.escape(str(key))}</td><td>{value}</td></tr>"

    return rows


def render_metadata(metadata):
    labels = {
        "app_name": "Application",
        "package_name": "Package / Bundle ID",
        "scan_type": "Artifact type",
        "client": "Client",
        "consultant": "Consultant",
        "source": "Evidence source",
    }
    rows = []
    for key, label in labels.items():
        value = metadata.get(key)
        if value:
            rows.append(
                f"<tr><th>{html.escape(label)}</th>"
                f"<td>{html.escape(str(value))}</td></tr>"
            )
    return "".join(rows) or '<tr><td colspan="2">Not supplied.</td></tr>'


def executive_summary(findings):
    critical = sum(1 for item in findings if item.severity.casefold() == "critical")
    high = sum(1 for item in findings if item.severity.casefold() == "high")
    if critical:
        posture = "Immediate remediation is recommended before release."
    elif high:
        posture = "High-severity issues should be addressed before release."
    elif findings:
        posture = "The assessment identified issues requiring engineering review."
    else:
        posture = "No reportable findings were imported from the supplied evidence."
    return (
        f"Astranyx evaluated {len(findings)} normalized, evidence-backed findings. "
        f"{posture} Scanner output should be independently validated before a "
        "security or compliance decision is made."
    )


def render_finding_rows(findings):
    rows = ""

    for i, finding in enumerate(findings):
        band = confidence_band(finding.confidence)
        mapping = get_mapping(finding.category)
        preview_html = render_source_preview(finding)

        rows += f"""
<tr class="finding-row {band}" data-band="{band}" data-category="{html.escape(finding.category)}">
  <td><button class="toggle" onclick="toggleDetails({i})">▶</button></td>
  <td>{html.escape(finding.severity)}</td>
  <td><span class="badge {band}">{finding.confidence}%</span></td>
  <td>{html.escape(finding.review_state.replace("_", " ").title())}</td>
  <td>{html.escape(finding.category)}</td>
  <td class="file">{html.escape(finding.file)}</td>
  <td>{finding.line}</td>
  <td>{html.escape(finding.reason)}</td>
</tr>
<tr id="details-{i}" class="details">
  <td colspan="8">
    <div class="details-box">
      <h4>Source Preview</h4>
      <div class="source-preview">{preview_html}</div>

      <h4>Evidence</h4>
      <pre>{html.escape(finding.evidence)}</pre>

      <h4>Classification</h4>
      <p>
        <strong>ID:</strong> {html.escape(finding.fingerprint)} |
        <strong>Source:</strong> {html.escape(finding.source)} |
        <strong>Rule:</strong> {html.escape(finding.rule_id or "n/a")}<br>
        <strong>CWE:</strong> {html.escape(mapping["cwe"])} |
        <strong>OWASP:</strong> {html.escape(mapping["owasp"])} |
        <strong>CVSS:</strong> {html.escape(mapping["cvss"])}
      </p>
      <p><strong>OWASP MASVS:</strong> {html.escape(", ".join(finding.masvs) or "Unmapped")} |
      <strong>Mapping basis:</strong> {html.escape(finding.masvs_mapping)}</p>

      <h4>Recommendation</h4>
      <p>{html.escape(recommendation(finding))}</p>

      <h4>Note</h4>
      <p>{html.escape(finding.note)}</p>

      <h4>Tester Review</h4>
      <p><strong>State:</strong> {html.escape(finding.review_state.replace("_", " ").title())}</p>
      <p>{html.escape(finding.review_note or "No tester decision recorded.")}</p>
    </div>
  </td>
</tr>
"""

    return rows


def _csv_cell(value):
    """Prevent imported text from becoming a spreadsheet formula."""
    if isinstance(value, str) and value.startswith(SPREADSHEET_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def write_csv(findings, output_dir):
    with (output_dir / "findings.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "fingerprint",
                "severity",
                "confidence",
                "review_state",
                "review_note",
                "masvs",
                "masvs_mapping",
                "category",
                "file",
                "line",
                "reason",
                "evidence",
            ]
        )

        for item in findings:
            writer.writerow(
                map(
                    _csv_cell,
                    [
                        item.fingerprint,
                        item.severity,
                        item.confidence,
                        item.review_state,
                        item.review_note,
                        ";".join(item.masvs),
                        item.masvs_mapping,
                        item.category,
                        item.file,
                        item.line,
                        item.reason,
                        item.evidence,
                    ],
                )
            )


def copy_assets(output_dir):
    for asset in ("style.css", "app.js"):
        shutil.copyfile(TEMPLATE_DIR / asset, output_dir / asset)


def render(report, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    findings = sorted(report.findings, key=lambda f: (-f.confidence, f.file, f.line))
    summary = report.summary()
    attack_surface = build_attack_surface(findings)

    high = sum(1 for f in findings if f.confidence >= 80)
    medium = sum(1 for f in findings if 40 <= f.confidence < 80)
    low = sum(1 for f in findings if f.confidence < 40)

    overall_risk_score = calculate(findings)
    risk_rating = rating(overall_risk_score)
    risk_bar = "█" * (overall_risk_score // 5)
    risk_bar += "░" * (20 - len(risk_bar))

    category_labels = list(summary["categories"].keys())
    category_values = list(summary["categories"].values())
    severity_counts = {
        level: sum(1 for finding in findings if finding.severity.casefold() == level)
        for level in ("critical", "high", "medium", "low", "info")
    }

    page = load_template("dashboard.html")

    replacements = {
        "{{TARGET}}": html.escape(summary["target"]),
        "{{GENERATED}}": html.escape(summary["generated"]),
        "{{ASSESSMENT_TITLE}}": html.escape(
            str(report.metadata.get("assessment_title") or "Mobile Security Assessment")
        ),
        "{{EXECUTIVE_SUMMARY}}": html.escape(executive_summary(findings)),
        "{{METADATA_ROWS}}": render_metadata(report.metadata),
        "{{OVERALL_RISK_SCORE}}": str(overall_risk_score),
        "{{RISK_RATING}}": html.escape(risk_rating),
        "{{RISK_BAR}}": risk_bar,
        "{{CONFIDENCE_SCORE}}": str(confidence_score(findings)),
        "{{TOTAL}}": str(summary["total"]),
        "{{HIGH}}": str(high),
        "{{MEDIUM}}": str(medium),
        "{{LOW}}": str(low),
        "{{CRITICAL_SEVERITY}}": str(severity_counts["critical"]),
        "{{HIGH_SEVERITY}}": str(severity_counts["high"]),
        "{{MEDIUM_SEVERITY}}": str(severity_counts["medium"]),
        "{{LOW_SEVERITY}}": str(severity_counts["low"]),
        "{{INFO_SEVERITY}}": str(severity_counts["info"]),
        "{{SURFACE_ROWS}}": render_surface_rows(attack_surface),
        "{{FINDING_ROWS}}": render_finding_rows(findings),
        "{{CATEGORY_LABELS}}": json.dumps(category_labels),
        "{{CATEGORY_VALUES}}": json.dumps(category_values),
        "{{CATEGORY_COUNT}}": str(len(category_labels)),
    }

    for key, value in replacements.items():
        page = page.replace(key, value)

    (output_dir / "index.html").write_text(page, encoding="utf-8")
    (output_dir / "findings.json").write_text(report.to_json(), encoding="utf-8")

    write_csv(findings, output_dir)
    copy_assets(output_dir)
