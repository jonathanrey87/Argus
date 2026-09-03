import json
from pathlib import Path

import pytest

from astranyx.modules.js import analyze


def test_analyze_javascript_patterns_and_routes(
    tmp_path,
):
    bundle = tmp_path / "app.js"
    bundle.write_text(
        """
        fetch("/api/profile");
        axios.get("https://example.com/api/status");
        const token = "placeholder";
        """,
        encoding="utf-8",
    )

    report = analyze(tmp_path)

    assert report["target"] == tmp_path.name
    assert report["files_analyzed"] == 1

    findings = report["summary"]["app.js"]

    assert findings["network_fetch"] == 1
    assert findings["axios"] == 1
    assert findings["auth"] == 1
    assert "uploads" not in findings

    assert report["routes"] == [
        "/api/profile",
        "https://example.com/api/status",
    ]


def test_analyze_detects_whole_word_upload_pattern(tmp_path):
    bundle = tmp_path / "upload.js"
    bundle.write_text(
        'const attachment = "evidence";',
        encoding="utf-8",
    )

    report = analyze(tmp_path)

    assert report["summary"]["upload.js"]["uploads"] == 1


def test_analyze_writes_json_report(tmp_path):
    source = tmp_path / "source"
    source.mkdir()

    bundle = source / "bundle.js"
    bundle.write_text(
        'fetch("/api/test");',
        encoding="utf-8",
    )

    output = tmp_path / "reports" / "report.json"

    report = analyze(
        source,
        output=output,
    )

    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_analyze_rejects_missing_path(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(
        SystemExit,
        match="Path not found",
    ):
        analyze(missing)


def test_analyze_rejects_file_path(tmp_path):
    source_file = tmp_path / "app.js"
    source_file.write_text(
        "const value = 1;",
        encoding="utf-8",
    )

    with pytest.raises(
        SystemExit,
        match="Path is not a directory",
    ):
        analyze(source_file)


def test_analyze_rejects_empty_directory(tmp_path):
    with pytest.raises(
        SystemExit,
        match="No JavaScript files found",
    ):
        analyze(tmp_path)


def test_analyze_skips_unreadable_files(
    tmp_path,
    monkeypatch,
):
    good_file = tmp_path / "good.js"
    good_file.write_text(
        'fetch("/api/good");',
        encoding="utf-8",
    )

    broken_file = tmp_path / "broken.js"
    broken_file.write_text(
        "placeholder",
        encoding="utf-8",
    )

    original_read_text = Path.read_text

    def controlled_read_text(path, *args, **kwargs):
        if path == broken_file:
            raise OSError("simulated read failure")

        return original_read_text(
            path,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        Path,
        "read_text",
        controlled_read_text,
    )

    report = analyze(tmp_path)

    assert report["files_analyzed"] == 1
    assert "good.js" in report["summary"]
    assert "broken.js" not in report["summary"]


def test_analyze_emits_hashed_source_backed_signals(tmp_path):
    bundle = tmp_path / "app.js"
    bundle.write_text(
        'function safe() {}\nlocalStorage.setItem("sessionToken", token);\neval(input);',
        encoding="utf-8",
    )

    report = analyze(tmp_path)

    assert report["source_files"][0]["path"] == "app.js"
    assert len(report["source_files"][0]["sha256"]) == 64
    execution = [
        signal
        for signal in report["signals"]
        if signal["category"] == "dynamic_code_execution"
    ]
    assert [signal["match"] for signal in execution] == ["eval("]
    assert execution[0]["line"] == 3
    assert execution[0]["status"] == "candidate"


def test_analyze_extracts_api_methods_without_ui_route_confusion(tmp_path):
    bundle = tmp_path / "app.js"
    bundle.write_text(
        'link="/network/profile";const endpoint=`${api}/public/admin/recover`;'
        "return getHttpPostResolver(endpoint, {});",
        encoding="utf-8",
    )

    report = analyze(tmp_path)

    assert [
        (endpoint["method"], endpoint["path"]) for endpoint in report["api_endpoints"]
    ] == [("POST", "/public/admin/recover")]
    assert report["report_guidance"].startswith("Signals are review candidates")
