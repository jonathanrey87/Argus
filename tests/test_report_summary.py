from astranyx.core.finding import Finding
from astranyx.core.report import Report


def _finding(severity, confidence):
    return Finding(
        category=f"{severity} example",
        severity=severity,
        file="app",
        full_path="",
        line=1,
        evidence=severity,
        note="test",
        confidence=confidence,
    )


def test_summary_counts_severity_not_confidence():
    report = Report(
        "demo",
        [
            _finding("Critical", 10),
            _finding("High", 70),
            _finding("Medium", 99),
            _finding("Low", 50),
            _finding("Info", 90),
        ],
    )

    summary = report.summary()

    assert {
        level: summary[level] for level in ("critical", "high", "medium", "low", "info")
    } == {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}


def test_summary_exposes_cvss_coverage_and_severity_disagreements():
    assessed = _finding("Medium", 90)
    assessed.assess_cvss(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        source="manual",
    )

    summary = Report("demo", [assessed, _finding("Low", 50)]).summary()

    assert summary["cvss_assessed"] == 1
    assert summary["cvss_unassessed"] == 1
    assert summary["cvss_highest"] == 9.8
    assert summary["cvss_severity_mismatches"] == 1
