"""Evidence-backed authorization policy differential analysis.

The analyzer deliberately operates on explicit route and policy facts.  It does
not infer that a nearby authorization-looking call is effective; extractors are
expected to emit only controls that guard the represented operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from astranyx.analysis.pipeline import AnalysisStage
from astranyx.core.finding import Finding


CONTROL_KINDS = frozenset(
    {"authentication", "capability", "ownership", "role", "tenant", "object_state"}
)
EXPOSURES = frozenset({"public", "authenticated", "internal", "unknown"})


def _bounded_identifier(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 256:
        raise ValueError(f"{label} must be between 1 and 256 characters")
    return normalized


@dataclass(frozen=True, slots=True, order=True)
class AuthorizationControl:
    """A security predicate that must hold before an operation is allowed."""

    id: str
    kind: str
    evidence: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _bounded_identifier(self.id, "control ID"))
        if self.kind not in CONTROL_KINDS:
            raise ValueError(f"unsupported authorization control kind: {self.kind}")
        if not self.evidence.strip():
            raise ValueError("authorization controls require explicit evidence")


@dataclass(frozen=True, slots=True)
class AccessPath:
    """One externally or internally reachable path to a protected operation."""

    id: str
    asset: str
    operation: str
    route: str
    method: str
    controls: tuple[AuthorizationControl, ...] = ()
    exposure: str = "unknown"
    file: str = ""
    line: int = 0
    evidence: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _bounded_identifier(self.id, "access path ID"))
        object.__setattr__(self, "asset", _bounded_identifier(self.asset, "asset"))
        object.__setattr__(
            self, "operation", _bounded_identifier(self.operation, "operation")
        )
        if not self.route.strip() or not self.method.strip():
            raise ValueError("access paths require a route and method")
        if self.exposure not in EXPOSURES:
            raise ValueError(f"unsupported access-path exposure: {self.exposure}")
        if self.line < 0:
            raise ValueError("access-path line cannot be negative")
        control_ids = [control.id for control in self.controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("access paths cannot contain duplicate control IDs")


@dataclass(frozen=True, slots=True)
class AuthorizationPolicy:
    """The explicit controls required for an asset operation."""

    id: str
    asset: str
    operation: str
    required_controls: tuple[AuthorizationControl, ...]
    evidence: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _bounded_identifier(self.id, "policy ID"))
        object.__setattr__(self, "asset", _bounded_identifier(self.asset, "asset"))
        object.__setattr__(
            self, "operation", _bounded_identifier(self.operation, "operation")
        )
        if not self.required_controls:
            raise ValueError("authorization policies require at least one control")
        if not self.evidence.strip():
            raise ValueError("authorization policies require explicit evidence")
        control_ids = [control.id for control in self.required_controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("policies cannot contain duplicate control IDs")


@dataclass(frozen=True, slots=True)
class AuthorizationDifferential:
    """An access path that fails an explicit authorization contract."""

    policy_id: str
    path_id: str
    asset: str
    operation: str
    route: str
    method: str
    missing_controls: tuple[str, ...]
    policy_evidence: str
    path_evidence: str
    file: str
    line: int

    def to_finding(self) -> Finding:
        missing = ", ".join(self.missing_controls)
        location = f"{self.file}:{self.line}" if self.file else self.route
        evidence = (
            f"{self.method.upper()} {self.route} reaches {self.asset}:{self.operation} "
            f"without required control(s) {missing}; path evidence: "
            f"{self.path_evidence or location}; policy evidence: {self.policy_evidence}"
        )
        return Finding(
            category="Authorization Policy Differential",
            severity="high",
            file=self.file or self.route,
            full_path=self.file or self.route,
            line=self.line,
            evidence=evidence,
            note="Validate that the alternate path can reach the protected operation.",
            confidence=85,
            reason="An explicit authorization contract is not enforced on this path.",
            rule_id="authorization-policy-differential",
        )


class AuthorizationDifferentialAnalyzer:
    """Compare effective path controls against explicit policy contracts."""

    def analyze(
        self,
        paths: Iterable[AccessPath],
        policies: Iterable[AuthorizationPolicy],
    ) -> list[AuthorizationDifferential]:
        path_list = sorted(paths, key=lambda item: item.id)
        policy_list = sorted(policies, key=lambda item: item.id)
        policy_keys: set[tuple[str, str]] = set()
        results: list[AuthorizationDifferential] = []

        for policy in policy_list:
            key = (policy.asset, policy.operation)
            if key in policy_keys:
                raise ValueError(
                    "multiple authorization policies cover the same asset operation"
                )
            policy_keys.add(key)
            required = {control.id for control in policy.required_controls}
            for path in path_list:
                if (path.asset, path.operation) != key:
                    continue
                present = {control.id for control in path.controls}
                missing = tuple(sorted(required - present))
                if not missing:
                    continue
                results.append(
                    AuthorizationDifferential(
                        policy.id,
                        path.id,
                        path.asset,
                        path.operation,
                        path.route,
                        path.method.upper(),
                        missing,
                        policy.evidence,
                        path.evidence,
                        path.file,
                        path.line,
                    )
                )
        return results


class AuthorizationDifferentialStage(AnalysisStage):
    """Pipeline adapter for authorization differential correlation."""

    name = "authorization_differential"

    def __init__(
        self,
        *,
        paths_key: str = "authorization_paths",
        policies_key: str = "authorization_policies",
        output_key: str = "authorization_differentials",
        findings_key: str = "findings",
    ) -> None:
        self.paths_key = paths_key
        self.policies_key = policies_key
        self.output_key = output_key
        self.findings_key = findings_key

    def run(self, context: dict) -> None:
        paths = context.get(self.paths_key, [])
        policies = context.get(self.policies_key, [])
        if not isinstance(paths, list) or not all(
            isinstance(item, AccessPath) for item in paths
        ):
            raise TypeError("authorization paths must be AccessPath objects")
        if not isinstance(policies, list) or not all(
            isinstance(item, AuthorizationPolicy) for item in policies
        ):
            raise TypeError(
                "authorization policies must be AuthorizationPolicy objects"
            )
        findings = context.setdefault(self.findings_key, [])
        if not isinstance(findings, list) or not all(
            isinstance(item, Finding) for item in findings
        ):
            raise TypeError("authorization findings must be normalized Finding objects")

        differentials = AuthorizationDifferentialAnalyzer().analyze(paths, policies)
        context[self.output_key] = differentials
        findings.extend(item.to_finding() for item in differentials)
