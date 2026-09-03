from datetime import UTC, datetime

import pytest

from astranyx.engagement.policy import EngagementPolicy, PolicyError


def policy(**overrides):
    data = {
        "engagement_id": "H1-WICKR-2026",
        "authorization_reference": "HackerOne program scope",
        "targets": [
            {"pattern": "admin.wickr.com", "schemes": ["https"], "ports": [443]},
            {"pattern": "*.owned.example", "schemes": ["https"], "ports": [443]},
        ],
        "exclusions": [
            {"pattern": "support.wickr.com", "schemes": ["https"], "ports": [443]}
        ],
        "mode": "safe_active",
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "max_requests_per_second": 5,
        "user_agent": "wickrvrpresearcher_jrm87",
    }
    data.update(overrides)
    return EngagementPolicy.from_dict(data)


def test_authorizes_exact_target_and_denies_suffix_confusion():
    engagement = policy()
    assert engagement.authorize("https://admin.wickr.com/admin/").allowed
    assert not engagement.authorize("https://admin.wickr.com.attacker.example/").allowed


def test_wildcard_requires_a_real_subdomain():
    engagement = policy()
    assert engagement.authorize("https://callback.owned.example/").allowed
    assert not engagement.authorize("https://owned.example/").allowed


def test_exclusion_wins_and_credentials_are_denied():
    engagement = policy(
        targets=[{"pattern": "*.wickr.com", "schemes": ["https"], "ports": [443]}]
    )
    assert not engagement.authorize("https://support.wickr.com/").allowed
    assert not engagement.authorize("https://user:pass@admin.wickr.com/").allowed


def test_state_change_requires_explicit_active_authority():
    with pytest.raises(PolicyError, match="state-changing"):
        policy(allowed_methods=["GET", "POST"])

    engagement = policy(
        mode="active_validation",
        allowed_methods=["GET", "POST"],
        allow_state_changing=True,
    )
    assert engagement.authorize("https://admin.wickr.com/test", "POST").allowed
    assert not engagement.authorize("https://admin.wickr.com/test", "DELETE").allowed


def test_expired_policy_fails_closed():
    engagement = policy(expires_at="2026-09-01T00:00:00Z")
    decision = engagement.authorize(
        "https://admin.wickr.com/",
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )
    assert not decision.allowed
    assert "expired" in decision.reason


@pytest.mark.parametrize("rate", [0, -1, 101])
def test_rejects_unsafe_rate_limits(rate):
    with pytest.raises(PolicyError, match="max_requests_per_second"):
        policy(max_requests_per_second=rate)


@pytest.mark.parametrize(
    "url",
    [
        "https://admin.wickr.com.attacker.example/",
        "https://admin.wickr.com@attacker.example/",
        "https://attacker.example/?next=https://admin.wickr.com/",
        "https://admin.wickr.com%2eattacker.example/",
        "https://admin.wickr.com\\@attacker.example/",
        "file://admin.wickr.com/etc/passwd",
        "https://admin.wickr.com:444/",
        "https://admin.wickr.com/\nHost: attacker.example",
    ],
)
def test_scope_confusion_inputs_fail_closed(url):
    assert not policy().authorize(url).allowed


def test_user_agent_rejects_header_injection():
    with pytest.raises(PolicyError, match="control characters"):
        policy(user_agent="researcher\r\nHost: attacker.example")


def test_rejects_invalid_allowed_resolved_network():
    with pytest.raises(PolicyError, match="resolved network"):
        policy(allowed_resolved_networks=["not-a-network"])


def test_resolution_policy_denies_private_by_default_and_allows_explicit_cidr():
    engagement = policy()
    assert not engagement.authorize_resolved_address(
        "https://admin.wickr.com/", "127.0.0.1"
    ).allowed
    internal = policy(allowed_resolved_networks=["10.0.0.0/8"])
    assert internal.authorize_resolved_address(
        "https://admin.wickr.com/", "10.1.2.3"
    ).allowed
