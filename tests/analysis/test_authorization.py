import pytest

from astranyx.analysis.authorization import (
    AccessPath,
    AuthorizationControl,
    AuthorizationDifferentialAnalyzer,
    AuthorizationDifferentialStage,
    AuthorizationPolicy,
)


VIEW = AuthorizationControl(
    "job-listing:view", "capability", "job_manager_user_can_view_job_listing"
)


def policy():
    return AuthorizationPolicy(
        "wpjm-view-policy",
        "job-listing",
        "read",
        (VIEW,),
        "The standard REST controller gates listing reads with the view capability.",
    )


def test_finds_alternate_route_missing_required_capability():
    standard = AccessPath(
        "standard-item",
        "job-listing",
        "read",
        "/wp/v2/job-listings/{id}",
        "GET",
        (VIEW,),
        "public",
        "includes/class-rest-api.php",
        120,
        "view capability dominates response preparation",
    )
    internal = AccessPath(
        "promoted-item",
        "job-listing",
        "read",
        "/wpjm-internal/v1/promoted-jobs/{id}",
        "GET",
        (),
        "public",
        "includes/promoted-jobs/class-api.php",
        80,
        "permission_callback is __return_true",
    )

    results = AuthorizationDifferentialAnalyzer().analyze(
        [internal, standard], [policy()]
    )

    assert len(results) == 1
    assert results[0].path_id == "promoted-item"
    assert results[0].missing_controls == ("job-listing:view",)
    finding = results[0].to_finding()
    assert finding.rule_id == "authorization-policy-differential"
    assert finding.severity == "high"
    assert "__return_true" in finding.evidence


def test_requires_exact_control_identity_not_only_same_control_kind():
    wrong_capability = AuthorizationControl(
        "job-listing:edit", "capability", "current_user_can('edit_job')"
    )
    path = AccessPath(
        "item",
        "job-listing",
        "read",
        "/jobs/{id}",
        "GET",
        (wrong_capability,),
    )
    result = AuthorizationDifferentialAnalyzer().analyze([path], [policy()])
    assert result[0].missing_controls == ("job-listing:view",)


def test_stage_appends_normalized_findings_without_discarding_existing():
    context = {
        "authorization_paths": [
            AccessPath(
                "public-item",
                "job-listing",
                "read",
                "/internal/jobs/{id}",
                "GET",
            )
        ],
        "authorization_policies": [policy()],
        "findings": [],
    }
    AuthorizationDifferentialStage().run(context)
    assert len(context["authorization_differentials"]) == 1
    assert context["findings"][0].category == "Authorization Policy Differential"


def test_rejects_ambiguous_duplicate_policy_contracts():
    with pytest.raises(ValueError, match="multiple authorization policies"):
        AuthorizationDifferentialAnalyzer().analyze([], [policy(), policy()])


def test_models_reject_unknown_control_and_exposure_values():
    with pytest.raises(ValueError, match="control kind"):
        AuthorizationControl("check", "csrf", "nonce verified")
    with pytest.raises(ValueError, match="exposure"):
        AccessPath("path", "asset", "read", "/asset", "GET", exposure="internet")
