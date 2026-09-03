import json
import multiprocessing
import time
from dataclasses import dataclass, field

import pytest

from astranyx.engagement.http import (
    AuthorizedHttpClient,
    RateLimiter,
    RequestDenied,
    RequestSpec,
    ResponseLimitExceeded,
    TransportResponse,
    UrllibTransport,
)
from astranyx.engagement.ledger import AuditLedger
from astranyx.engagement.network import SharedRateLimiter
from astranyx.engagement.policy import EngagementPolicy


def policy(**overrides):
    data = {
        "engagement_id": "eng-http",
        "authorization_reference": "signed authorization",
        "targets": [
            {"pattern": "app.example.test", "schemes": ["https"], "ports": [443]}
        ],
        "mode": "safe_active",
        "allowed_methods": ["GET"],
        "max_requests_per_second": 5,
        "user_agent": "astranyx-authorized-test",
    }
    data.update(overrides)
    return EngagementPolicy.from_dict(data)


@dataclass
class FakeTransport:
    responses: list[TransportResponse]
    requests: list[RequestSpec] = field(default_factory=list)

    def send(self, request):
        self.requests.append(request)
        return self.responses.pop(0)


def response(status=200, headers=None, body=b"ok", url="https://app.example.test/"):
    return TransportResponse(status, headers or {}, body, url)


def client(tmp_path, fake, engagement=None, limiter=None):
    active_policy = engagement or policy()
    return AuthorizedHttpClient(
        active_policy,
        AuditLedger(tmp_path / "ledger.jsonl", active_policy.engagement_id),
        transport=fake,
        limiter=limiter,
        resolver=FakeResolver(),
    )


class FakeResolver:
    def __init__(self, addresses=("93.184.216.34",)):
        self.addresses = addresses
        self.calls = []

    def resolve(self, host, port):
        self.calls.append((host, port))
        return self.addresses


def _shared_limiter_worker(path, barrier, results):
    limiter = SharedRateLimiter(path, 20)
    barrier.wait()
    limiter.wait("https://app.example.test/")
    results.put(time.time())


def test_authorized_request_forces_policy_user_agent_and_seals_response(tmp_path):
    fake = FakeTransport([response(body=b"evidence")])
    result = client(tmp_path, fake).send(
        RequestSpec("https://app.example.test/", headers={"User-Agent": "override"})
    )

    assert result.body == b"evidence"
    assert fake.requests[0].headers["User-Agent"] == "astranyx-authorized-test"
    assert AuditLedger(tmp_path / "ledger.jsonl", "eng-http").verify().records == 3


def test_out_of_scope_request_never_reaches_transport(tmp_path):
    fake = FakeTransport([response()])
    with pytest.raises(RequestDenied, match="outside"):
        client(tmp_path, fake).send(RequestSpec("https://outside.example/"))
    assert fake.requests == []


def test_redirect_is_reauthorized_and_cross_scope_hop_is_blocked(tmp_path):
    fake = FakeTransport(
        [response(302, {"Location": "https://outside.example/callback"}, b"")]
    )
    with pytest.raises(RequestDenied, match="outside"):
        client(tmp_path, fake).send(RequestSpec("https://app.example.test/start"))
    assert len(fake.requests) == 1


def test_in_scope_redirect_is_followed_with_bounded_hops(tmp_path):
    fake = FakeTransport(
        [
            response(302, {"Location": "/final"}, b""),
            response(200, {}, b"done", "https://app.example.test/final"),
        ]
    )
    result = client(tmp_path, fake).send(RequestSpec("https://app.example.test/start"))
    assert result.body == b"done"
    assert [item.url for item in fake.requests] == [
        "https://app.example.test/start",
        "https://app.example.test/final",
    ]


def test_rate_limiter_paces_requests_with_injected_clock():
    moments = iter([0.0, 0.0, 0.5])
    sleeps = []
    limiter = RateLimiter(2, clock=lambda: next(moments), sleeper=sleeps.append)
    limiter.wait()
    limiter.wait()
    assert sleeps == [0.5]


def test_rejects_authority_override_headers_before_transport(tmp_path):
    fake = FakeTransport([response()])
    with pytest.raises(RequestDenied, match="authority"):
        client(tmp_path, fake).send(
            RequestSpec(
                "https://app.example.test/", headers={"Host": "outside.example"}
            )
        )
    assert fake.requests == []


def test_rejects_body_on_safe_method(tmp_path):
    fake = FakeTransport([response()])
    with pytest.raises(RequestDenied, match="body"):
        client(tmp_path, fake).send(
            RequestSpec("https://app.example.test/", method="GET", body=b"mutate=true")
        )
    assert fake.requests == []


def test_client_enforces_response_limit_for_custom_transport(tmp_path):
    fake = FakeTransport([response(body=b"12345")])
    with pytest.raises(ResponseLimitExceeded):
        client(tmp_path, fake).send(
            RequestSpec("https://app.example.test/", max_response_bytes=4)
        )


def test_transport_failure_is_recorded_without_secret_headers(tmp_path):
    class FailingTransport:
        def send(self, request):
            raise OSError("connection failed with token=do-not-log")

    ledger_path = tmp_path / "ledger.jsonl"
    active_policy = policy()
    http_client = AuthorizedHttpClient(
        active_policy,
        AuditLedger(ledger_path, active_policy.engagement_id),
        transport=FailingTransport(),
        resolver=FakeResolver(),
    )
    with pytest.raises(OSError):
        http_client.send(
            RequestSpec(
                "https://app.example.test/?token=do-not-log",
                headers={"Authorization": "Bearer do-not-log"},
            )
        )

    records = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    assert [record["event"] for record in records] == [
        "request.authorization",
        "request.resolution",
        "request.error",
    ]
    assert "do-not-log" not in ledger_path.read_text()


def test_303_redirect_changes_post_to_get_and_drops_body(tmp_path):
    engagement = policy(
        mode="active_validation",
        allowed_methods=["GET", "POST"],
        allow_state_changing=True,
    )
    fake = FakeTransport(
        [
            response(303, {"Location": "/complete"}, b""),
            response(200, {}, b"done", "https://app.example.test/complete"),
        ]
    )
    result = client(tmp_path, fake, engagement).send(
        RequestSpec("https://app.example.test/start", method="POST", body=b"test=true")
    )
    assert result.status == 200
    assert [(item.method, item.body) for item in fake.requests] == [
        ("POST", b"test=true"),
        ("GET", None),
    ]


def test_header_newlines_are_rejected_before_transport(tmp_path):
    fake = FakeTransport([response()])
    with pytest.raises(RequestDenied, match="control"):
        client(tmp_path, fake).send(
            RequestSpec(
                "https://app.example.test/", headers={"X-Test": "ok\r\nHost: bad"}
            )
        )
    assert fake.requests == []


def test_default_transport_ignores_environment_proxy_configuration(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    transport = UrllibTransport()
    proxy_handlers = [
        handler
        for handler in transport.opener.handlers
        if isinstance(handler, __import__("urllib.request").request.ProxyHandler)
    ]
    assert proxy_handlers == []


def test_cross_origin_redirect_strips_credentials(tmp_path):
    engagement = policy(
        targets=[{"pattern": "*.example.test", "schemes": ["https"], "ports": [443]}]
    )
    fake = FakeTransport(
        [
            response(302, {"Location": "https://other.example.test/final"}, b""),
            response(200, {}, b"done", "https://other.example.test/final"),
        ]
    )
    client(tmp_path, fake, engagement).send(
        RequestSpec(
            "https://app.example.test/start",
            headers={
                "Authorization": "Bearer sensitive",
                "Cookie": "session=sensitive",
                "X-Research": "preserved",
            },
        )
    )
    assert fake.requests[0].headers["Authorization"] == "Bearer sensitive"
    assert "Authorization" not in fake.requests[1].headers
    assert "Cookie" not in fake.requests[1].headers
    assert fake.requests[1].headers["X-Research"] == "preserved"


def test_non_global_dns_result_is_denied_before_transport(tmp_path):
    fake = FakeTransport([response()])
    active_policy = policy()
    http_client = AuthorizedHttpClient(
        active_policy,
        AuditLedger(tmp_path / "ledger.jsonl", active_policy.engagement_id),
        transport=fake,
        resolver=FakeResolver(("127.0.0.1",)),
    )
    with pytest.raises(RequestDenied, match="non-global"):
        http_client.send(RequestSpec("https://app.example.test/"))
    assert fake.requests == []


def test_explicit_network_allows_internal_authorized_target(tmp_path):
    engagement = policy(allowed_resolved_networks=["10.20.0.0/16"])
    fake = FakeTransport([response()])
    http_client = AuthorizedHttpClient(
        engagement,
        AuditLedger(tmp_path / "ledger.jsonl", engagement.engagement_id),
        transport=fake,
        resolver=FakeResolver(("10.20.1.8",)),
    )
    http_client.send(RequestSpec("https://app.example.test/"))
    assert fake.requests[0].resolved_ip == "10.20.1.8"


def test_mixed_public_and_private_dns_answer_fails_closed(tmp_path):
    fake = FakeTransport([response()])
    http_client = AuthorizedHttpClient(
        policy(),
        AuditLedger(tmp_path / "ledger.jsonl", "eng-http"),
        transport=fake,
        resolver=FakeResolver(("93.184.216.34", "169.254.169.254")),
    )
    with pytest.raises(RequestDenied, match="non-global"):
        http_client.send(RequestSpec("https://app.example.test/"))
    assert fake.requests == []


def test_shared_rate_limiter_coordinates_independent_instances(tmp_path):
    clock_values = iter([100.0, 100.0])
    sleeps = []
    first = SharedRateLimiter(
        tmp_path / "rate.json",
        2,
        clock=lambda: next(clock_values),
        sleeper=sleeps.append,
    )
    second = SharedRateLimiter(
        tmp_path / "rate.json",
        2,
        clock=lambda: next(clock_values),
        sleeper=sleeps.append,
    )
    first.wait("https://app.example.test/")
    second.wait("https://app.example.test/")
    assert sleeps == [0.5]


@pytest.mark.skipif(__import__("os").name == "nt", reason="fork stress test")
def test_shared_rate_limiter_coordinates_processes(tmp_path):
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(4)
    results = context.Queue()
    processes = [
        context.Process(
            target=_shared_limiter_worker,
            args=(tmp_path / "rate.json", barrier, results),
        )
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    moments = sorted(results.get(timeout=5) for _ in processes)
    for process in processes:
        process.join(timeout=5)
        assert process.exitcode == 0
    assert moments[-1] - moments[0] >= 0.13
