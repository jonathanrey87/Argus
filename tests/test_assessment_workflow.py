import json

import pytest

from astranyx.assessment import workflow
from astranyx.importers import mobsf


def mobsf_report():
    return {
        "app_name": "Tester App",
        "package_name": "com.example.tester",
        "code_analysis": {
            "findings": {
                "insecure_storage": {
                    "metadata": {
                        "severity": "high",
                        "description": "Sensitive data may be stored insecurely",
                    },
                    "files": {"src/Storage.java": "21"},
                }
            }
        },
        "manifest_analysis": {"manifest_findings": []},
    }


def test_assess_defaults_to_needs_validation_and_verifies_bundle(tmp_path):
    source = tmp_path / "mobsf.json"
    output = tmp_path / "assessment"
    source.write_text(json.dumps(mobsf_report()))

    result = workflow.run(source, output, client="Example Client")
    report = json.loads((output / "findings.json").read_text())

    assert result["integrity_verified"] is True
    assert result["review_states"]["needs_validation"] == 1
    assert report["findings"][0]["review_state"] == "needs_validation"
    assert report["metadata"]["client"] == "Example Client"
    template = json.loads((output / "reviews.template.json").read_text())
    fingerprint = report["findings"][0]["fingerprint"]
    assert template["reviews"][fingerprint] == {
        "note": "",
        "state": "needs_validation",
    }


def test_assess_applies_fingerprint_review_decisions(tmp_path):
    source = tmp_path / "mobsf.json"
    reviews = tmp_path / "reviews.json"
    output = tmp_path / "assessment"
    source.write_text(json.dumps(mobsf_report()))
    _, findings = mobsf.load(source)
    fingerprint = findings[0].fingerprint
    reviews.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reviews": {
                    fingerprint: {
                        "state": "confirmed",
                        "note": "Reproduced during authorized testing.",
                    }
                },
            }
        )
    )

    result = workflow.run(source, output, review_file=reviews)
    report = json.loads((output / "findings.json").read_text())

    assert result["review_states"]["confirmed"] == 1
    assert report["findings"][0]["review_state"] == "confirmed"
    assert "Reproduced" in report["findings"][0]["review_note"]
    assert "Confirmed" in (output / "index.html").read_text()


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "root must be an object"),
        ({}, "schema_version must be 1"),
        (
            {
                "schema_version": 1,
                "reviews": {"asx-unknown": {"state": "confirmed"}},
            },
            "unknown finding",
        ),
        (
            {
                "schema_version": 1,
                "reviews": {"asx-unknown": {"state": "maybe"}},
            },
            "invalid review state",
        ),
    ],
)
def test_assess_rejects_invalid_review_files(tmp_path, payload, message):
    source = tmp_path / "mobsf.json"
    reviews = tmp_path / "reviews.json"
    output = tmp_path / "assessment"
    source.write_text(json.dumps(mobsf_report()))
    reviews.write_text(json.dumps(payload))

    with pytest.raises(workflow.AssessmentError, match=message):
        workflow.run(source, output, review_file=reviews)
