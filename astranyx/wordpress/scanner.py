from collections import Counter
from pathlib import Path

from astranyx.core.finding import Finding
from astranyx.core.html import render
from astranyx.core.report import Report
from astranyx.core.sarif import export as export_sarif
from astranyx.wordpress.analyzer import analyze_finding
from astranyx.wordpress.rules.registry import get_rules_for_file
from astranyx.wordpress.taint import analyze as taint_analyze


def make_note(category):
    notes = {
        "Public AJAX Route": "Unauthenticated AJAX endpoint. Review callback for authentication, nonce validation, and capability checks.",
        "Public REST Permission": "Public REST endpoint. Verify authorization inside the callback.",
        "Possible Unsafe SQL": "User-controlled input may reach SQL.",
        "SSRF Sink": "Review whether attacker-controlled URLs can reach outbound requests.",
        "Upload Handler": "Review upload validation, MIME checks, and destination path.",
        "Deserialization": "Review whether serialized input can be attacker-controlled.",
        "Dangerous Function": "Determine whether attacker-controlled input reaches this execution sink.",
        "Dynamic Include": "Determine whether the included path is user-controlled.",
        "React Dangerous Sink": "Verify that HTML is escaped or sanitized before rendering.",
        "DOM Sink": "Review whether user-controlled HTML reaches innerHTML.",
        "HTML Escaping": "Escaping detected.",
    }
    return notes.get(category, "Manual review recommended.")


def is_comment(line):
    stripped = line.strip()
    return stripped.startswith(("//", "#", "*", "/*"))


def scan_file(path: Path, root: Path):
    findings = []

    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return findings

    rules = get_rules_for_file(path)

    for idx, line in enumerate(lines, start=1):
        if is_comment(line):
            continue

        for rule in rules:
            if rule["pattern"].search(line):
                finding = Finding(
                    category=rule["category"],
                    severity=rule["severity"],
                    file=str(path.relative_to(root)),
                    full_path=str(path),
                    line=idx,
                    evidence=line.strip()[:250],
                    note=make_note(rule["category"]),
                )

                finding = analyze_finding(finding, lines)
                findings.append(finding)

    if path.suffix == ".php":
        for tf in taint_analyze(lines):
            findings.append(
                Finding(
                    category="Potential Taint Flow",
                    severity="High",
                    file=str(path.relative_to(root)),
                    full_path=str(path),
                    line=1,
                    evidence=f"{tf.variable} -> {tf.sink}",
                    note=tf.reason,
                    confidence=tf.confidence,
                    reason=tf.reason,
                )
            )

    return findings


def summarize(findings):
    summary = {}
    for f in findings:
        summary[f.category] = summary.get(f.category, 0) + 1
    return summary


def scan_plugin(plugin_path, recursive=True):
    root = Path(plugin_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(root)

    findings = []

    for ext in ("*.php", "*.js", "*.jsx", "*.ts", "*.tsx"):
        files = root.rglob(ext) if recursive else root.glob(ext)
        for file in files:
            if any(x in file.parts for x in ("vendor", "node_modules", ".git")):
                continue

            findings.extend(scan_file(file, root))

    return findings


def run(plugin_path, output=None, recursive=True):
    """Scan a WordPress plugin and return its report metadata."""
    plugin_path = Path(plugin_path).expanduser().resolve()
    findings = scan_plugin(plugin_path, recursive=recursive)
    summary = summarize(findings)

    print()
    print("=" * 60)
    print("Astranyx WordPress Security Audit")
    print("=" * 60)
    print()

    print("Summary")
    print("-------")
    for k, v in sorted(summary.items()):
        print(f"{k:28} {v}")

    print()
    print("Findings")
    print("--------")

    findings.sort(key=lambda f: (-f.confidence, f.file, f.line))

    for f in findings:
        print(f"[{f.severity}] {f.category}")
        print(f"Confidence : {f.confidence}%")
        print(f"Reason     : {f.reason}")
        print(f"Location   : {f.file}:{f.line}")
        print(f"Evidence   : {f.evidence}")
        print()

    print(f"Total Findings: {len(findings)}")

    report = Report(str(plugin_path), findings)
    out = Path(output) if output else Path("reports") / Path(plugin_path).name
    render(report, out)
    export_sarif(report, out)

    print()
    print("=" * 60)
    print("Astranyx Report Generated")
    print("=" * 60)
    print(f"HTML : {out / 'index.html'}")
    print(f"JSON : {out / 'findings.json'}")
    print(f"CSV  : {out / 'findings.csv'}")
    print(f"SARIF: {out / 'findings.sarif'}")

    severity_counts = Counter(finding.severity.lower() for finding in findings)

    return {
        "target": str(plugin_path),
        "findings_total": len(findings),
        "categories": summary,
        "severity": {
            level: severity_counts.get(level, 0)
            for level in ("critical", "high", "medium", "low", "info")
        },
        "output_directory": str(out),
        "artifacts": [
            str(out / filename)
            for filename in (
                "index.html",
                "findings.json",
                "findings.csv",
                "findings.sarif",
            )
        ],
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage:")
        print("python -m astranyx.wordpress.scanner <plugin_directory>")
        raise SystemExit(1)

    run(sys.argv[1])
