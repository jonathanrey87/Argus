import csv
import json

import pytest

from astranyx.importers import mobsf


def sample_report():
    return {
        "app_name": "Example Wallet",
        "package_name": "com.example.wallet",
        "scan_type": "apk",
        "code_analysis": {
            "android_insecure_random": {
                "metadata": {
                    "severity": "warning",
                    "description": "<b>Insecure random generator</b>",
                },
                "files": {
                    "../java/com/example/Crypto.java": {
                        "lines": "42, 44",
                        "match_string": "<code>new Random()</code>",
                    }
                },
            },
            "android_certificate_pinning": {
                "metadata": {
                    "severity": "secure",
                    "description": "Certificate pinning is implemented",
                }
            },
        },
        "manifest_analysis": {
            "manifest_findings": [
                {
                    "rule": "android_exported_activity",
                    "title": "Exported activity",
                    "severity": "high",
                    "description": "Activity is externally reachable",
                    "component": "com.example.DeepLinkActivity",
                }
            ]
        },
    }


def test_load_normalizes_high_signal_mobsf_findings(tmp_path):
    source = tmp_path / "mobsf.json"
    source.write_text(json.dumps(sample_report()))

    metadata, findings = mobsf.load(source)

    assert metadata == {
        "source": "mobsf",
        "app_name": "Example Wallet",
        "package_name": "com.example.wallet",
        "scan_type": "apk",
        "normalized_findings": 2,
    }
    assert {finding.rule_id for finding in findings} == {
        "android_insecure_random",
        "android_exported_activity",
    }
    code = next(item for item in findings if item.rule_id == "android_insecure_random")
    assert code.severity == "Medium"
    assert code.file == "java/com/example/Crypto.java"
    assert code.line == 42
    assert code.evidence == "new Random()"
    assert "<b>" not in code.note
    assert code.source == "mobsf"


def test_import_report_writes_normalized_artifacts(tmp_path):
    source = tmp_path / "mobsf.json"
    output = tmp_path / "report"
    source.write_text(json.dumps(sample_report()))

    result = mobsf.import_report(source, output)
    normalized = json.loads((output / "findings.json").read_text())
    sarif = json.loads((output / "findings.sarif").read_text())

    assert result["findings_imported"] == 2
    assert normalized["schema_version"] == 1
    assert all(item["source"] == "mobsf" for item in normalized["findings"])
    assert sarif["runs"][0]["results"][0]["partialFingerprints"]
    assert (output / "index.html").is_file()
    assert (output / "findings.csv").is_file()


@pytest.mark.parametrize("payload", [[], {}, {"permissions": {}}])
def test_load_rejects_non_report_shapes(tmp_path, payload):
    source = tmp_path / "invalid.json"
    source.write_text(json.dumps(payload))

    with pytest.raises(mobsf.MobSFImportError, match="invalid MobSF report"):
        mobsf.load(source)


def test_load_enforces_report_size_limit(tmp_path, monkeypatch):
    source = tmp_path / "large.json"
    source.write_text("{}")
    monkeypatch.setattr(mobsf, "MAX_REPORT_BYTES", 1)

    with pytest.raises(mobsf.MobSFImportError, match="safety limit"):
        mobsf.load(source)


def test_import_neutralizes_spreadsheet_formulas(tmp_path):
    source = tmp_path / "mobsf.json"
    output = tmp_path / "report"
    payload = sample_report()
    payload["manifest_analysis"]["manifest_findings"][0][
        "component"
    ] = '=HYPERLINK("https://attacker.invalid")'
    source.write_text(json.dumps(payload))

    mobsf.import_report(source, output)
    rows = list(csv.DictReader((output / "findings.csv").open()))

    exported = next(row for row in rows if row["category"] == "Exported activity")
    assert exported["evidence"].startswith("'=HYPERLINK")
