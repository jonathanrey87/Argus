import hashlib
import json
from importlib.resources import files

import pytest

from astranyx.comparison import retest
from astranyx.core.finding import Finding
from astranyx.core.report import Report


def finding(category, evidence, severity="Medium", confidence=70, file="app.java"):
    return Finding(
        category=category,
        severity=severity,
        file=file,
        full_path="",
        line=10,
        evidence=evidence,
        note="Review this finding",
        reason="Review this finding",
        confidence=confidence,
        source="mobsf",
        rule_id=category.casefold().replace(" ", "_"),
    )


def write_report(path, findings):
    path.write_text(Report("com.example.app", findings).to_json())


def test_compare_classifies_retest_outcomes(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    write_report(
        baseline,
        [
            finding("Persistent", "same"),
            finding("Fixed", "removed"),
            finding("Changed", "old evidence"),
            finding("Regression", "same", severity="Low"),
        ],
    )
    write_report(
        current,
        [
            finding("Persistent", "same"),
            finding("New", "added"),
            finding("Changed", "new evidence"),
            finding("Regression", "same", severity="High"),
        ],
    )

    result = retest.compare(baseline, current)

    assert result["summary"] == {
        "baseline_total": 4,
        "current_total": 4,
        "new": 1,
        "fixed": 1,
        "persistent": 1,
        "changed": 1,
        "regressed": 1,
    }
    assert result["fixed"][0]["category"] == "Fixed"
    assert result["new"][0]["category"] == "New"
    assert result["changed"][0]["changes"]["evidence"] == {
        "before": "old evidence",
        "after": "new evidence",
    }
    assert result["regressed"][0]["changes"]["severity"] == {
        "before": "Low",
        "after": "High",
    }


def test_write_report_creates_sealed_retest_bundle(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    output = tmp_path / "retest"
    write_report(baseline, [finding("Fixed", "removed")])
    write_report(current, [])

    result = retest.write_report(baseline, current, output)
    manifest = json.loads((output / "manifest.json").read_text())
    schema = json.loads(
        files("astranyx").joinpath("schemas/retest-report.schema.json").read_text()
    )

    assert result["fixed"] == 1
    assert schema["properties"]["comparison_type"]["const"] == "baseline_retest"
    assert (output / "retest.json").is_file()
    assert "Fixed: 1" in (output / "retest.md").read_text()
    for artifact in manifest["artifacts"]:
        path = output / artifact["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]

    with pytest.raises(retest.RetestError, match="refusing to overwrite"):
        retest.write_report(baseline, current, output)


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "root must be an object"),
        ({"schema_version": 2, "findings": []}, "unsupported report schema"),
        ({"schema_version": 1, "findings": ["bad"]}, "findings must be objects"),
        (
            {"schema_version": 1, "findings": [{"fingerprint": "invalid"}]},
            "invalid finding fingerprint",
        ),
    ],
)
def test_compare_rejects_invalid_reports(tmp_path, payload, message):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps(payload))
    write_report(current, [])

    with pytest.raises(retest.RetestError, match=message):
        retest.compare(baseline, current)
