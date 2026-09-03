"""Fail-closed rules-of-engagement validation and request authorization."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
SUPPORTED_METHODS = SAFE_METHODS | STATE_CHANGING_METHODS
SUPPORTED_MODES = frozenset({"passive", "safe_active", "active_validation"})


class PolicyError(ValueError):
    """Raised when a rules-of-engagement policy is unsafe or malformed."""


def _hostname(value: str) -> str:
    host = value.casefold().rstrip(".")
    if not host or any(character.isspace() for character in host):
        raise PolicyError(f"invalid hostname pattern: {value!r}")
    return host


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise PolicyError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise PolicyError("engagement timestamps must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """An exact host, IP address, CIDR, or leftmost-label wildcard rule."""

    pattern: str
    schemes: tuple[str, ...] = ("https",)
    ports: tuple[int, ...] = (443,)

    def __post_init__(self) -> None:
        pattern = _hostname(self.pattern)
        if "*" in pattern and not pattern.startswith("*."):
            raise PolicyError("wildcards are allowed only as the leftmost '*.' label")
        if pattern.count("*") > 1:
            raise PolicyError("scope patterns may contain at most one wildcard")
        schemes = tuple(sorted({scheme.casefold() for scheme in self.schemes}))
        if not schemes or any(scheme not in {"http", "https"} for scheme in schemes):
            raise PolicyError("scope schemes must contain only http or https")
        ports = tuple(sorted(set(self.ports)))
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise PolicyError("scope ports must be between 1 and 65535")
        object.__setattr__(self, "pattern", pattern)
        object.__setattr__(self, "schemes", schemes)
        object.__setattr__(self, "ports", ports)

    def matches(self, host: str, scheme: str, port: int) -> bool:
        if scheme.casefold() not in self.schemes or port not in self.ports:
            return False
        candidate = _hostname(host)
        try:
            network = ipaddress.ip_network(self.pattern, strict=False)
            address = ipaddress.ip_address(candidate)
        except ValueError:
            network = None
            address = None
        if network is not None and address is not None:
            return address in network
        if self.pattern.startswith("*."):
            suffix = self.pattern[2:]
            return candidate.endswith("." + suffix) and candidate != suffix
        return candidate == self.pattern


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """A deterministic allow/deny decision with audit-friendly reasoning."""

    allowed: bool
    reason: str
    method: str
    url: str
    matched_scope: str | None = None
    mode: str = "passive"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EngagementPolicy:
    """Validated engagement authority used as a fail-closed execution gate."""

    engagement_id: str
    authorization_reference: str
    targets: tuple[ScopeRule, ...]
    exclusions: tuple[ScopeRule, ...] = field(default_factory=tuple)
    mode: str = "passive"
    allowed_methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    allow_state_changing: bool = False
    max_requests_per_second: float = 1.0
    user_agent: str = ""
    allow_non_global_addresses: bool = False
    allowed_resolved_networks: tuple[str, ...] = field(default_factory=tuple)
    starts_at: datetime | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.engagement_id.strip():
            raise PolicyError("engagement_id is required")
        if not self.authorization_reference.strip():
            raise PolicyError("authorization_reference is required")
        if not self.targets:
            raise PolicyError("at least one target scope rule is required")
        if self.mode not in SUPPORTED_MODES:
            raise PolicyError(f"unsupported engagement mode: {self.mode!r}")
        methods = tuple(sorted({method.upper() for method in self.allowed_methods}))
        unsupported = set(methods) - SUPPORTED_METHODS
        if unsupported:
            raise PolicyError(f"unsupported HTTP methods: {sorted(unsupported)}")
        if set(methods) & STATE_CHANGING_METHODS and (
            self.mode != "active_validation" or not self.allow_state_changing
        ):
            raise PolicyError(
                "state-changing methods require active_validation mode and "
                "allow_state_changing=true"
            )
        if not 0 < self.max_requests_per_second <= 100:
            raise PolicyError(
                "max_requests_per_second must be greater than 0 and at most 100"
            )
        if not self.user_agent.strip():
            raise PolicyError("a researcher-identifying user_agent is required")
        if any(
            ord(character) < 32 or ord(character) == 127
            for character in self.user_agent
        ):
            raise PolicyError("user_agent must not contain control characters")
        if self.starts_at and self.expires_at and self.starts_at >= self.expires_at:
            raise PolicyError("starts_at must be before expires_at")
        networks = []
        for value in self.allowed_resolved_networks:
            try:
                networks.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as exc:
                raise PolicyError(
                    f"invalid allowed resolved network: {value!r}"
                ) from exc
        object.__setattr__(self, "allowed_methods", methods)
        object.__setattr__(
            self, "allowed_resolved_networks", tuple(sorted(set(networks)))
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementPolicy:
        if not isinstance(data, dict):
            raise PolicyError("policy root must be a JSON object")

        def rules(key: str) -> tuple[ScopeRule, ...]:
            raw_rules = data.get(key, [])
            if not isinstance(raw_rules, list):
                raise PolicyError(f"{key} must be a list")
            try:
                return tuple(ScopeRule(**rule) for rule in raw_rules)
            except (TypeError, AttributeError) as exc:
                raise PolicyError(f"invalid {key} rule") from exc

        raw_networks = data.get("allowed_resolved_networks", [])
        if not isinstance(raw_networks, list) or not all(
            isinstance(value, str) for value in raw_networks
        ):
            raise PolicyError("allowed_resolved_networks must be a list of strings")

        return cls(
            engagement_id=str(data.get("engagement_id", "")),
            authorization_reference=str(data.get("authorization_reference", "")),
            targets=rules("targets"),
            exclusions=rules("exclusions"),
            mode=str(data.get("mode", "passive")),
            allowed_methods=tuple(data.get("allowed_methods", SAFE_METHODS)),
            allow_state_changing=bool(data.get("allow_state_changing", False)),
            max_requests_per_second=float(data.get("max_requests_per_second", 1.0)),
            user_agent=str(data.get("user_agent", "")),
            allow_non_global_addresses=bool(
                data.get("allow_non_global_addresses", False)
            ),
            allowed_resolved_networks=tuple(raw_networks),
            starts_at=_parse_time(data.get("starts_at")),
            expires_at=_parse_time(data.get("expires_at")),
        )

    @classmethod
    def load(cls, path: str | Path) -> EngagementPolicy:
        policy_path = Path(path).expanduser()
        try:
            data = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"unable to load policy {policy_path}: {exc}") from exc
        return cls.from_dict(data)

    def authorize(
        self,
        url: str,
        method: str = "GET",
        *,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        normalized_method = method.upper()
        base = {
            "method": normalized_method,
            "url": url,
            "mode": self.mode,
        }

        current = (now or datetime.now(UTC)).astimezone(UTC)
        if self.starts_at and current < self.starts_at:
            return AuthorizationDecision(False, "engagement has not started", **base)
        if self.expires_at and current >= self.expires_at:
            return AuthorizationDecision(
                False, "engagement authorization has expired", **base
            )
        if normalized_method not in self.allowed_methods:
            return AuthorizationDecision(False, "HTTP method is not authorized", **base)
        if (
            normalized_method in STATE_CHANGING_METHODS
            and not self.allow_state_changing
        ):
            return AuthorizationDecision(
                False, "state-changing requests are disabled", **base
            )

        parsed = urlsplit(url)
        if any(ord(character) < 32 or ord(character) == 127 for character in url):
            return AuthorizationDecision(
                False, "URL contains control characters", **base
            )
        if parsed.username is not None or parsed.password is not None:
            return AuthorizationDecision(
                False, "credentials in URLs are prohibited", **base
            )
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return AuthorizationDecision(
                False, "URL must use http or https and include a host", **base
            )
        try:
            port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
        except ValueError:
            return AuthorizationDecision(False, "URL contains an invalid port", **base)

        for rule in self.exclusions:
            if rule.matches(parsed.hostname, parsed.scheme, port):
                return AuthorizationDecision(
                    False,
                    "target is explicitly excluded",
                    matched_scope=rule.pattern,
                    **base,
                )
        for rule in self.targets:
            if rule.matches(parsed.hostname, parsed.scheme, port):
                return AuthorizationDecision(
                    True,
                    "request is authorized by engagement policy",
                    matched_scope=rule.pattern,
                    **base,
                )
        return AuthorizationDecision(
            False, "target is outside engagement scope", **base
        )

    def authorize_resolved_address(
        self, url: str, address: str
    ) -> AuthorizationDecision:
        """Authorize a DNS result independently of hostname scope authorization."""
        base = self.authorize(url)
        if not base.allowed:
            return base
        try:
            candidate = ipaddress.ip_address(address)
        except ValueError:
            return AuthorizationDecision(
                False,
                "resolver returned an invalid IP address",
                base.method,
                url,
                mode=self.mode,
            )
        parsed = urlsplit(url)
        if parsed.hostname:
            try:
                literal = ipaddress.ip_address(parsed.hostname)
            except ValueError:
                literal = None
            if literal == candidate:
                return base
        if self.allow_non_global_addresses or candidate.is_global:
            return base
        if any(
            candidate in ipaddress.ip_network(value)
            for value in self.allowed_resolved_networks
        ):
            return base
        return AuthorizationDecision(
            False,
            "resolved address is non-global and not explicitly authorized",
            base.method,
            url,
            matched_scope=base.matched_scope,
            mode=self.mode,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "authorization_reference": self.authorization_reference,
            "mode": self.mode,
            "targets": [asdict(rule) for rule in self.targets],
            "exclusions": [asdict(rule) for rule in self.exclusions],
            "allowed_methods": list(self.allowed_methods),
            "allow_state_changing": self.allow_state_changing,
            "max_requests_per_second": self.max_requests_per_second,
            "user_agent": self.user_agent,
            "allow_non_global_addresses": self.allow_non_global_addresses,
            "allowed_resolved_networks": list(self.allowed_resolved_networks),
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
