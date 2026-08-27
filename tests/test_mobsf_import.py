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
        "imported_sections": ["code_analysis", "manifest_analysis"],
        "unsupported_sections": [],
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

    result = mobsf.import_report(
        source,
        output,
        client="Example <Client>",
        consultant="Assessment Team",
    )
    normalized = json.loads((output / "findings.json").read_text())
    sarif = json.loads((output / "findings.sarif").read_text())
    page = (output / "index.html").read_text()
    manifest = json.loads((output / "manifest.json").read_text())

    assert result["findings_imported"] == 2
    assert normalized["schema_version"] == 1
    assert all(item["source"] == "mobsf" for item in normalized["findings"])
    assert normalized["metadata"]["client"] == "Example <Client>"
    assert sarif["runs"][0]["results"][0]["partialFingerprints"]
    assert (output / "index.html").is_file()
    assert (output / "findings.csv").is_file()
    assert "Example &lt;Client&gt;" in page
    assert "https://cdn" not in page
    assert {item["path"] for item in manifest["artifacts"]} == {
        "app.js",
        "findings.csv",
        "findings.json",
        "findings.sarif",
        "index.html",
        "reviews.template.json",
        "style.css",
    }

    with pytest.raises(mobsf.MobSFImportError, match="refusing to overwrite"):
        mobsf.import_report(source, output)


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


def test_load_supports_current_mobsf_wrappers_and_security_sections(tmp_path):
    source = tmp_path / "current-mobsf.json"
    source.write_text(
        json.dumps(
            {
                "app_name": "Current Format",
                "code_analysis": {
                    "summary": {"high": 1},
                    "findings": {
                        "android_logging": {
                            "metadata": {
                                "severity": "high",
                                "description": "Sensitive logging",
                                "masvs": "MASVS-STORAGE-2",
                            },
                            "files": {"src/App.java": "17,18"},
                        }
                    },
                },
                "manifest_analysis": {"manifest_findings": []},
                "network_security": {
                    "network_findings": [
                        {
                            "scope": ["*"],
                            "description": "Cleartext traffic is allowed",
                            "severity": "high",
                        }
                    ]
                },
                "certificate_analysis": {
                    "certificate_findings": [
                        [
                            "warning",
                            "Application uses the v1 signature scheme",
                            "Legacy signing scheme",
                        ]
                    ]
                },
                "binary_analysis": [
                    {
                        "name": "lib/example.so",
                        "nx": {
                            "severity": "high",
                            "description": "NX is disabled",
                        },
                    }
                ],
                "permissions": {},
                "trackers": {},
            }
        )
    )

    metadata, findings = mobsf.load(source)

    assert len(findings) == 4
    code = next(item for item in findings if item.rule_id == "android_logging")
    assert code.line == 17
    assert code.evidence == "Sensitive logging"
    assert code.masvs == ["MASVS-STORAGE-2"]
    assert code.masvs_mapping == "upstream"
    assert metadata["imported_sections"] == [
        "binary_analysis",
        "certificate_analysis",
        "code_analysis",
        "manifest_analysis",
        "network_security",
    ]
    assert metadata["unsupported_sections"] == ["permissions", "trackers"]
