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
