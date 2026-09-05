from astranyx.wordpress.authorization import (
    analyze_plugin_authorization,
    extract_plugin_access_paths,
    extract_rest_access_paths,
)
from astranyx.wordpress.scanner import scan_plugin


def test_extracts_public_rest_route_and_handler_capability(tmp_path):
    source = tmp_path / "api.php"
    source.write_text(
        """<?php
register_rest_route(
    'wpjm-internal/v1',
    '/promoted-jobs/(?P<id>\\d+)',
    [
        'methods' => WP_REST_Server::READABLE,
        'callback' => [ $this, 'get_job_data' ],
        'permission_callback' => '__return_true',
    ]
);

function get_job_data($request) {
    if (! job_manager_user_can_view_job_listing($request['id'])) {
        return new WP_Error('rest_post_invalid_id');
    }
    return prepare_item_for_response($request['id']);
}
""",
        encoding="utf-8",
    )

    paths = extract_rest_access_paths(source, root=tmp_path)

    assert len(paths) == 1
    path = paths[0]
    assert path.route == "/wpjm-internal/v1/promoted-jobs/(?P<id>\\d+)"
    assert path.method == "GET"
    assert path.exposure == "public"
    assert [control.id for control in path.controls] == [
        "capability-function:job_manager_user_can_view_job_listing"
    ]
    assert path.file == "api.php"
    assert path.line == 2


def test_extracts_controls_from_permission_and_handler_callbacks(tmp_path):
    source = tmp_path / "routes.php"
    source.write_text(
        """<?php
function permission() {
    return is_user_logged_in() && current_user_can('manage_options');
}
function update_item() {
    return current_user_can('edit_posts');
}
register_rest_route('demo/v1', '/items', [
    'methods' => 'post',
    'callback' => 'update_item',
    'permission_callback' => 'permission',
]);
""",
        encoding="utf-8",
    )

    path = extract_rest_access_paths(source)[0]
    assert path.method == "POST"
    assert path.exposure == "unknown"
    assert [control.id for control in path.controls] == [
        "authentication:wordpress-user",
        "capability:edit_posts",
        "capability:manage_options",
    ]


def test_plugin_extraction_is_deterministic_and_skips_vendor(tmp_path):
    (tmp_path / "z.php").write_text(
        "<?php register_rest_route('z/v1', '/z', "
        "['callback'=>'z', 'permission_callback'=>'__return_true']);",
        encoding="utf-8",
    )
    (tmp_path / "a.php").write_text(
        "<?php register_rest_route('a/v1', '/a', "
        "['callback'=>'a', 'permission_callback'=>'__return_true']);",
        encoding="utf-8",
    )
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "ignored.php").write_text(
        "<?php register_rest_route('bad/v1', '/bad', []);", encoding="utf-8"
    )

    paths = extract_plugin_access_paths(tmp_path)
    assert [path.file for path in paths] == ["a.php", "z.php"]


def test_extracts_legacy_php_array_callback_syntax(tmp_path):
    source = tmp_path / "legacy.php"
    source.write_text(
        "<?php register_rest_route('demo/v1', '/legacy', array("
        "'callback' => array($this, 'read_item'), "
        "'permission_callback' => array($this, 'can_read')));",
        encoding="utf-8",
    )
    path = extract_rest_access_paths(source)[0]
    assert path.asset == "wordpress-rest:read_item"
    assert path.evidence == "permission callback: can_read"


def test_correlates_wpjm_policy_with_unprotected_internal_item_route(tmp_path):
    (tmp_path / "policy.php").write_text(
        """<?php
function gate_view_capability_for_single($response, $post) {
    if (job_manager_user_can_view_job_listing($post->ID)) {
        return $response;
    }
    return new WP_Error('rest_post_invalid_id');
}
""",
        encoding="utf-8",
    )
    (tmp_path / "internal.php").write_text(
        """<?php
register_rest_route('wpjm-internal/v1', '/promoted-jobs/(?P<id>\\d+)', [
    'methods' => WP_REST_Server::READABLE,
    'callback' => [ $this, 'get_job_data' ],
    'permission_callback' => '__return_true',
]);
function get_job_data($request) {
    $controller = get_post_type_object(
        WP_Job_Manager_Post_Types::PT_LISTING
    )->get_rest_controller();
    return $controller->prepare_item_for_response($request['id'], $request);
}
""",
        encoding="utf-8",
    )

    inventory = analyze_plugin_authorization(tmp_path)

    assert len(inventory.policies) == 1
    assert inventory.policies[0].asset == "wordpress-post-type:job_listing"
    assert inventory.policies[0].operation == "read_item"
    assert len(inventory.differentials) == 1
    differential = inventory.differentials[0]
    assert differential.path_id.startswith("wordpress-rest:internal.php")
    assert differential.missing_controls == (
        "capability-function:job_manager_user_can_view_job_listing",
    )
    scanner_findings = scan_plugin(tmp_path)
    assert any(
        finding.rule_id == "authorization-policy-differential"
        for finding in scanner_findings
    )


def test_does_not_correlate_route_without_concrete_matching_asset(tmp_path):
    (tmp_path / "plugin.php").write_text(
        """<?php
function policy($post) {
    return job_manager_user_can_view_job_listing($post->ID);
}
register_rest_route('demo/v1', '/unrelated/(?P<id>\\d+)', [
    'callback' => 'read_unrelated',
    'permission_callback' => '__return_true',
]);
function read_unrelated($request) { return get_option('public_value'); }
""",
        encoding="utf-8",
    )
    inventory = analyze_plugin_authorization(tmp_path)
    assert inventory.policies
    assert inventory.differentials == ()


def test_ambiguous_policy_functions_fail_closed_without_inventing_contract(tmp_path):
    (tmp_path / "policy.php").write_text(
        """<?php
function one($post) { return alpha_user_can_view_document($post->ID); }
function two($post) { return beta_user_can_view_document($post->ID); }
""",
        encoding="utf-8",
    )
    inventory = analyze_plugin_authorization(tmp_path)
    assert inventory.policies == ()
