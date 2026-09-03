"""Strict CVSS v3.1 base-vector scoring with no inferred metrics."""

from __future__ import annotations

import math
from dataclasses import dataclass

METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_VALUES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


class CVSSVectorError(ValueError):
    """Raised when a vector cannot be scored as a CVSS v3.1 base vector."""


@dataclass(frozen=True)
class CVSSAssessment:
    vector: str
    score: float
    severity: str


def _round_up(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def rating(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def _parse(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not vector.strip():
        raise CVSSVectorError("CVSS vector must be a non-empty string")
    parts = vector.strip().upper().split("/")
    if parts[0] != "CVSS:3.1":
        raise CVSSVectorError("only CVSS:3.1 base vectors are supported")

    metrics: dict[str, str] = {}
    for component in parts[1:]:
        if component.count(":") != 1:
            raise CVSSVectorError(f"invalid CVSS metric: {component!r}")
        name, value = component.split(":")
        if name not in METRIC_ORDER:
            raise CVSSVectorError(f"unsupported CVSS base metric: {name!r}")
        if name in metrics:
            raise CVSSVectorError(f"duplicate CVSS metric: {name}")
        metrics[name] = value

    missing = [name for name in METRIC_ORDER if name not in metrics]
    if missing:
        raise CVSSVectorError(f"missing CVSS base metrics: {', '.join(missing)}")
    if metrics["S"] not in {"U", "C"}:
        raise CVSSVectorError(f"invalid CVSS metric value: S:{metrics['S']}")
    for name in METRIC_ORDER:
        if name in {"PR", "S"}:
            continue
        if metrics[name] not in VALUES[name]:
            raise CVSSVectorError(f"invalid CVSS metric value: {name}:{metrics[name]}")
    if metrics["PR"] not in PR_VALUES[metrics["S"]]:
        raise CVSSVectorError(f"invalid CVSS metric value: PR:{metrics['PR']}")
    return metrics


def assess(vector: str) -> CVSSAssessment:
    """Validate and calculate a CVSS v3.1 base score."""
    metrics = _parse(vector)
    scope = metrics["S"]
    impact_subscore = 1 - (
        (1 - VALUES["C"][metrics["C"]])
        * (1 - VALUES["I"][metrics["I"]])
        * (1 - VALUES["A"][metrics["A"]])
    )
    if scope == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = (
            7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
        )

    exploitability = (
        8.22
        * VALUES["AV"][metrics["AV"]]
        * VALUES["AC"][metrics["AC"]]
        * PR_VALUES[scope][metrics["PR"]]
        * VALUES["UI"][metrics["UI"]]
    )
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _round_up(min(impact + exploitability, 10))
    else:
        score = _round_up(min(1.08 * (impact + exploitability), 10))

    canonical = "CVSS:3.1/" + "/".join(
        f"{name}:{metrics[name]}" for name in METRIC_ORDER
    )
    return CVSSAssessment(canonical, score, rating(score))
