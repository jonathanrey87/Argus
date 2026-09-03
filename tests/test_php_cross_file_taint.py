from astranyx.parsers.php import parse_file
from astranyx.wordpress.scanner import scan_plugin


def test_php_parser_and_wordpress_scanner_emit_cross_file_path(tmp_path):
    (tmp_path / "controller.php").write_text(
        """<?php
function handle() {
    $url = $_GET['url'];
    fetch_profile($url);
}
""",
        encoding="utf-8",
    )
    (tmp_path / "service.php").write_text(
        """<?php
function fetch_profile($candidate) {
    wp_remote_get($candidate);
}
""",
        encoding="utf-8",
    )

    parsed = parse_file(tmp_path / "controller.php", root=tmp_path)
    findings = scan_plugin(tmp_path)
    cross_file = [item for item in findings if item.category == "Cross-File Taint Flow"]

    assert parsed.path == "controller.php"
    assert len(cross_file) == 1
    assert cross_file[0].file == "service.php"
    assert cross_file[0].line == 3
    assert "controller.php:3" in cross_file[0].evidence
    assert "service.php:3" in cross_file[0].evidence


def test_php_scanner_does_not_claim_cross_file_flow_without_explicit_assignment(
    tmp_path,
):
    (tmp_path / "controller.php").write_text(
        """<?php
function handle($value) {
    fetch_profile($value);
}
""",
        encoding="utf-8",
    )
    (tmp_path / "one.php").write_text(
        "<?php function fetch_profile($value) { wp_remote_get($value); }",
        encoding="utf-8",
    )
    (tmp_path / "two.php").write_text(
        "<?php function fetch_profile($value) { wp_remote_get($value); }",
        encoding="utf-8",
    )

    findings = scan_plugin(tmp_path)

    assert not any(item.category == "Cross-File Taint Flow" for item in findings)
