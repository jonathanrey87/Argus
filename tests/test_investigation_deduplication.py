import json

from astranyx.investigation import deduplication


def finding(**overrides):
    value = {
        "fingerprint": "asx-0123456789abcdef01234567",
        "category": "SSRF Sink",
        "rule_id": "",
        "severity": "Medium",
        "confidence": 60,
        "file": "plugin.php",
        "evidence": "wp_remote_get($url)",
        "reason": "",
        "note": "Review outbound request.",
    }
    value.update(overrides)
    return value


def test_deduplicate_merges_matching_cross_module_observations():
    result = deduplication.deduplicate(
        {
            "javascript": [finding()],
            "wordpress": [
                finding(
                    severity="High",
                    confidence=95,
                    reason="Attacker-controlled URL reaches the request sink.",
                )
            ],
        }
    )

    assert result["observations"] == 2
    assert result["unique_findings"] == 1
    assert result["duplicates_removed"] == 1
    assert result["fingerprint_collisions"] == []
    assert result["findings"][0]["severity"] == "High"
    assert result["findings"][0]["modules"] == ["javascript", "wordpress"]
    assert result["findings"][0]["observations"] == 2


def test_deduplicate_preserves_fingerprint_collisions():
    fingerprint = "asx-0123456789abcdef01234567"
    result = deduplication.deduplicate(
        {
            "first": [finding(fingerprint=fingerprint)],
            "second": [
                finding(
                    fingerprint=fingerprint,
                    file="different.php",
                    evidence="different evidence",
                )
            ],
        }
    )

    assert result["unique_findings"] == 2
    assert result["duplicates_removed"] == 0
    assert result["fingerprint_collisions"] == [fingerprint]
    assert all(item["fingerprint_collision"] for item in result["findings"])


def test_deduplicate_preserves_findings_without_stable_fingerprints():
    result = deduplication.deduplicate(
        {
            "wordpress": [
                finding(fingerprint="legacy-fingerprint"),
                finding(fingerprint=None, file="other.php"),
            ]
        }
    )

    assert result["observations"] == 2
    assert result["unique_findings"] == 2
    assert result["duplicates_removed"] == 0
    assert [item["modules"] for item in result["findings"]] == [
        ["wordpress"],
        ["wordpress"],
    ]


def test_load_module_findings_ignores_signal_only_reports(tmp_path):
    normalized = tmp_path / "wordpress.json"
    normalized.write_text(
        json.dumps({"schema_version": 1, "findings": [finding()]}),
        encoding="utf-8",
    )
    signals = tmp_path / "javascript.json"
    signals.write_text(
        json.dumps({"summary": {"app.js": {"network_fetch": 1}}}),
        encoding="utf-8",
    )

    loaded = deduplication.load_module_findings(
        {
            "wordpress": {"finding_report": str(normalized)},
            "javascript": {"finding_report": str(signals)},
        }
    )

    assert loaded == {"wordpress": [finding()]}
