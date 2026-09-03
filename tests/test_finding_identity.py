import json
from dataclasses import replace
from importlib.resources import files

import pytest

from astranyx.core.finding import fingerprint
from astranyx.core.report import Report
from astranyx.wordpress.scanner import Finding


def make_finding(**changes):
    finding = Finding(
        category="SSRF Sink",
        severity="Medium",
        file="src/plugin.php",
        full_path="/checkout/src/plugin.php",
        line=12,
        evidence="wp_remote_get( $url );",
        note="Review the outbound request.",
    )
    return replace(finding, **changes) if changes else finding


def test_fingerprint_is_stable_across_line_and_checkout_changes():
    first = make_finding()
    moved = make_finding(line=99, full_path="/another/checkout/src/plugin.php")

    assert first.fingerprint == moved.fingerprint
    assert first.fingerprint.startswith("asx-")


def test_fingerprint_normalizes_case_paths_and_whitespace():
    assert fingerprint("SSRF Sink", "SRC/plugin.php", "call(  value )") == fingerprint(
        "ssrf sink", "src/plugin.php", "call( value )"
    )


def test_fingerprint_changes_with_security_identity():
    original = make_finding()

    assert make_finding(category="SQL Injection").fingerprint != original.fingerprint
    assert make_finding(file="src/other.php").fingerprint != original.fingerprint
    assert (
        make_finding(evidence="wp_remote_get($other)").fingerprint
        != original.fingerprint
    )


def test_report_declares_schema_and_fingerprint():
    payload = json.loads(Report("target", [make_finding()]).to_json())
    schema = json.loads(
        files("astranyx").joinpath("schemas/finding-report.schema.json").read_text()
    )

    assert payload["schema_version"] == 1
    assert payload["metadata"] == {}
    assert payload["findings"][0]["fingerprint"].startswith("asx-")
    assert schema["properties"]["schema_version"]["const"] == 1


def test_finding_records_validated_cvss_with_provenance():
    finding = make_finding()
    finding.assess_cvss(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        source="manual",
    )

    assert finding.cvss_score == 9.8
    assert finding.cvss_severity == "Critical"
    assert finding.cvss_source == "manual"


def test_finding_rejects_vector_without_provenance():
    with pytest.raises(ValueError, match="explicit provenance"):
        make_finding(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
