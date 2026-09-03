"""Policy-gated, bounded HTTP execution for authorized assessments."""

from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from astranyx.engagement.ledger import AuditLedger
from astranyx.engagement.network import SharedRateLimiter, SystemResolver
from astranyx.engagement.policy import EngagementPolicy


class RequestDenied(PermissionError):
    """Raised before transport use when a proposed request is unauthorized."""


class ResponseLimitExceeded(ValueError):
    """Raised when a response exceeds the configured evidence bound."""


class RedirectLimitExceeded(ValueError):
    """Raised when a response exceeds the authorized redirect-hop bound."""


@dataclass(frozen=True, slots=True)
class RequestSpec:
    url: str
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout_seconds: float = 15.0
    max_response_bytes: int = 1_048_576
    max_redirects: int = 3
    resolved_ip: str | None = None

    def __post_init__(self) -> None:
        if not 0 < self.timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be greater than 0 and at most 120")
        if not 1 <= self.max_response_bytes <= 10_485_760:
            raise ValueError("max_response_bytes must be between 1 byte and 10 MiB")
        if not 0 <= self.max_redirects <= 10:
            raise ValueError("max_redirects must be between 0 and 10")


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


class Transport(Protocol):
    def send(self, request: RequestSpec) -> TransportResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(host, port, **kwargs)

    def connect(self):
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(host, port, **kwargs)

    def connect(self):
        raw = socket.create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class UrllibTransport:
    """Pinned standard-library transport with hostname TLS verification."""

    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect
        )

    def send(self, request: RequestSpec) -> TransportResponse:
        if not request.resolved_ip:
            raise RequestDenied("transport requires a policy-approved resolved IP")
        parsed = urlsplit(request.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection_type = (
            _PinnedHTTPSConnection
            if parsed.scheme == "https"
            else _PinnedHTTPConnection
        )
        kwargs = {"timeout": request.timeout_seconds}
        if parsed.scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        connection = connection_type(
            parsed.hostname, port, request.resolved_ip, **kwargs
        )
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection.request(
            request.method, target, body=request.body, headers=dict(request.headers)
        )
        response = connection.getresponse()
        try:
            body = response.read(request.max_response_bytes + 1)
            if len(body) > request.max_response_bytes:
                raise ResponseLimitExceeded(
                    f"response exceeded {request.max_response_bytes} bytes"
                )
            return TransportResponse(
                response.status, dict(response.getheaders()), body, request.url
            )
        finally:
            connection.close()


class RateLimiter:
    """Per-client monotonic request pacing with injectable clock and sleeper."""

    def __init__(
        self,
        requests_per_second: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.interval = 1.0 / requests_per_second
        self.clock = clock
        self.sleeper = sleeper
        self.last_request: float | None = None
        self._lock = Lock()

    def wait(self, url: str = "") -> None:
        with self._lock:
            current = self.clock()
            if self.last_request is not None:
                remaining = self.interval - (current - self.last_request)
                if remaining > 0:
                    self.sleeper(remaining)
                    current = self.clock()
            self.last_request = current


class AuthorizedHttpClient:
    """Execute only requests authorized by a validated engagement policy."""

    REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
    AUTHORITY_HEADERS = frozenset({"host", ":authority"})
    REDIRECT_SENSITIVE_HEADERS = frozenset(
        {"authorization", "cookie", "proxy-authorization"}
    )

    def __init__(
        self,
        policy: EngagementPolicy,
        ledger: AuditLedger,
        *,
        transport: Transport | None = None,
        limiter: RateLimiter | None = None,
        resolver=None,
    ):
        if ledger.engagement_id != policy.engagement_id:
            raise ValueError("ledger and policy engagement IDs must match")
        self.policy = policy
        self.ledger = ledger
        self.transport = transport or UrllibTransport()
        self.limiter = limiter or SharedRateLimiter(
            ledger.path.with_name(ledger.path.name + ".rate"),
            policy.max_requests_per_second,
        )
        self.resolver = resolver or SystemResolver()

    def send(self, request: RequestSpec) -> TransportResponse:
        method = request.method.upper()
        url = request.url
        body = request.body
        credential_origin = self._origin(url)
        unsafe_headers = {
            str(key).casefold()
            for key in request.headers
            if str(key).casefold() in self.AUTHORITY_HEADERS
        }
        if unsafe_headers:
            self.ledger.append(
                "request.authorization",
                {
                    "url": url,
                    "method": method,
                    "allowed": False,
                    "reason": "caller-controlled authority headers are prohibited",
                },
            )
            raise RequestDenied("caller-controlled authority headers are prohibited")
        if body is not None and method in {"GET", "HEAD", "OPTIONS"}:
            self.ledger.append(
                "request.authorization",
                {
                    "url": url,
                    "method": method,
                    "allowed": False,
                    "reason": "request body is prohibited for safe methods",
                },
            )
            raise RequestDenied("request body is prohibited for safe methods")
        for key, value in request.headers.items():
            if any(character in str(key) + str(value) for character in ("\r", "\n")):
                raise RequestDenied("header control characters are prohibited")
        for hop in range(request.max_redirects + 1):
            decision = self.policy.authorize(url, method)
            self.ledger.append(
                "request.authorization",
                {
                    "url": url,
                    "method": method,
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "matched_scope": decision.matched_scope,
                    "redirect_hop": hop,
                },
            )
            if not decision.allowed:
                raise RequestDenied(decision.reason)

            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
            try:
                addresses = tuple(self.resolver.resolve(parsed.hostname, port))
                if not addresses:
                    raise RequestDenied("target hostname did not resolve")
                for address in addresses:
                    address_decision = self.policy.authorize_resolved_address(
                        url, address
                    )
                    self.ledger.append(
                        "request.resolution",
                        {
                            "url": url,
                            "address": address,
                            "allowed": address_decision.allowed,
                            "reason": address_decision.reason,
                        },
                    )
                    if not address_decision.allowed:
                        raise RequestDenied(address_decision.reason)
                resolved_ip = addresses[0]
            except Exception as exc:
                self.ledger.append(
                    "request.error",
                    {
                        "url": url,
                        "method": method,
                        "error_type": type(exc).__name__,
                        "reason": "DNS authorization failed",
                        "redirect_hop": hop,
                    },
                )
                raise

            headers = {
                str(key): str(value)
                for key, value in request.headers.items()
                if str(key).casefold() != "user-agent"
                and (
                    self._origin(url) == credential_origin
                    or str(key).casefold() not in self.REDIRECT_SENSITIVE_HEADERS
                )
            }
            headers["User-Agent"] = self.policy.user_agent
            attempt = RequestSpec(
                url=url,
                method=method,
                headers=headers,
                body=body,
                timeout_seconds=request.timeout_seconds,
                max_response_bytes=request.max_response_bytes,
                max_redirects=request.max_redirects,
                resolved_ip=resolved_ip,
            )
            try:
                self.limiter.wait(url)
                response = self.transport.send(attempt)
                if not isinstance(response.body, bytes):
                    raise TypeError("transport response body must be bytes")
                if len(response.body) > request.max_response_bytes:
                    raise ResponseLimitExceeded(
                        f"response exceeded {request.max_response_bytes} bytes"
                    )
            except Exception as exc:
                self.ledger.append(
                    "request.error",
                    {
                        "url": url,
                        "method": method,
                        "error_type": type(exc).__name__,
                        "reason": "request execution failed",
                        "redirect_hop": hop,
                    },
                )
                raise
            self.ledger.append(
                "request.response",
                {
                    "url": url,
                    "method": method,
                    "status": response.status,
                    "response_bytes": len(response.body),
                    "body_sha256": hashlib.sha256(response.body).hexdigest(),
                    "final_url": response.final_url,
                    "redirect_hop": hop,
                },
            )

            location = next(
                (
                    value
                    for key, value in response.headers.items()
                    if key.casefold() == "location"
                ),
                None,
            )
            if response.status not in self.REDIRECT_STATUSES or not location:
                return response
            if hop >= request.max_redirects:
                raise RedirectLimitExceeded("redirect limit exceeded")
            url = urljoin(url, location)
            if response.status == 303 or (
                response.status in {301, 302} and method == "POST"
            ):
                method = "GET"
                body = None
        raise RedirectLimitExceeded("redirect limit exceeded")

    @staticmethod
    def _origin(url: str) -> tuple[str, str | None, int | None]:
        parsed = urlsplit(url)
        try:
            port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
        except ValueError:
            port = None
        return parsed.scheme.casefold(), parsed.hostname, port
