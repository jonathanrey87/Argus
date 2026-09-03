from astranyx.investigation import dashboard


def test_dashboard_renders_checkpoint_data_and_escapes_findings(tmp_path):
    (tmp_path / "html").mkdir()
    output = dashboard.render(
        tmp_path,
        {
            "id": "INV-TEST",
            "target": "/tmp/<target>",
            "status": "partial",
            "created": "2026-08-29T00:00:00+00:00",
            "profile": "web",
            "selected_modules": ["javascript", "wordpress"],
        },
        {"javascript": {"files_analyzed": 1}},
        [{"module": "wordpress", "message": "stopped"}],
        {
            "duplicates_removed": 2,
            "fingerprint_collisions": ["asx-collision"],
            "findings": [
                {
                    "fingerprint": "asx-test",
                    "severity": "High",
                    "confidence": 91,
                    "cvss_score": 9.8,
                    "category": "<script>alert(1)</script>",
                    "file": "plugin.php",
                    "evidence": "request($url)",
                    "modules": ["wordpress"],
                }
            ],
        },
        {"summary": {"nodes": 4, "edges": 3}},
    )

    page = output.read_text(encoding="utf-8")
    assert "INV-TEST" in page
    assert "/tmp/&lt;target&gt;" in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<script>alert(1)</script>" not in page
    assert '<span class="status completed">completed</span>' in page
    assert '<span class="status failed">failed</span>' in page
    assert "Self-contained offline dashboard" in page
    assert "CVSS 3.1" in page
    assert "9.8" in page


def test_dashboard_handles_empty_findings(tmp_path):
    (tmp_path / "html").mkdir()
    output = dashboard.render(
        tmp_path,
        {"id": "INV-EMPTY", "selected_modules": []},
        {},
        [],
        {"findings": []},
        {"summary": {}},
    )

    assert "No normalized findings are currently available." in output.read_text()
