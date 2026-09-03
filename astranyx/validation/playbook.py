"""Generate non-executing, approval-gated validation plans from attack paths."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 67_108_864


@dataclass(frozen=True, slots=True)
class ValidationStep:
    order: int
    action: str
    objective: str
    expected_evidence: str
    stop_condition: str
    requires_approval: bool = False


@dataclass(frozen=True, slots=True)
class ValidationPlan:
    id: str
    attack_path_source: str
    attack_path_sink: str
    risk_score: float
    confidence: int
    status: str
    execution_allowed: bool
    prerequisites: tuple[str, ...]
    steps: tuple[ValidationStep, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_attack_path_report(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser()
    try:
        if source.stat().st_size > MAX_REPORT_BYTES:
            raise ValueError("attack-path report exceeds 64 MiB")
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load attack-path report: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("unsupported or malformed attack-path report")
    if not isinstance(document.get("graph"), dict) or not isinstance(
        document.get("attack_paths"), list
    ):
        raise TypeError("attack-path report requires graph and attack_paths")
    return document


def _validate_path(
    path: dict[str, Any],
    node_ids: set[str],
    graph_edges: set[tuple[str, str, str, str]],
) -> None:
    nodes = path.get("nodes")
    relations = path.get("relations")
    evidence = path.get("evidence")
    if not isinstance(nodes, (list, tuple)) or len(nodes) < 2:
        raise ValueError("attack path must contain at least two nodes")
    if not all(isinstance(node, str) and node in node_ids for node in nodes):
        raise ValueError("attack path references an unknown graph node")
    if not isinstance(relations, (list, tuple)) or len(relations) != len(nodes) - 1:
        raise ValueError("attack path relationship count is inconsistent")
    if not isinstance(evidence, (list, tuple)) or len(evidence) != len(relations):
        raise ValueError("attack path evidence count is inconsistent")
    confidence = path.get("confidence")
    risk_score = path.get("risk_score")
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        raise ValueError("attack path confidence is invalid")
    if not isinstance(risk_score, (int, float)) or not 0 <= risk_score <= 5:
        raise ValueError("attack path risk score is invalid")
    for source, target, relation, claim in zip(
        nodes[:-1], nodes[1:], relations, evidence, strict=True
    ):
        if (source, target, relation, claim) not in graph_edges:
            raise ValueError("attack path edge or evidence is absent from the graph")


def generate_plans(report: dict[str, Any]) -> list[ValidationPlan]:
    """Create plans only; execution remains false until a later approval workflow."""
    raw_nodes = report["graph"].get("nodes", [])
    if not isinstance(raw_nodes, list):
        raise TypeError("attack-path graph nodes must be a list")
    try:
        nodes = {node["id"]: node for node in raw_nodes}
    except (KeyError, TypeError) as exc:
        raise ValueError("malformed graph node") from exc
    raw_edges = report["graph"].get("edges", [])
    if not isinstance(raw_edges, list):
        raise TypeError("attack-path graph edges must be a list")
    try:
        graph_edges = {
            (edge["source"], edge["target"], edge["relation"], edge["evidence"])
            for edge in raw_edges
        }
    except (KeyError, TypeError) as exc:
        raise ValueError("malformed graph edge") from exc
    plans = []
    for path in report["attack_paths"]:
        if not isinstance(path, dict):
            raise TypeError("malformed attack path")
        _validate_path(path, set(nodes), graph_edges)
        source = path["source"]
        sink = path["sink"]
        if source != path["nodes"][0] or sink != path["nodes"][-1]:
            raise ValueError("attack path source or sink is inconsistent")
        identity = "\0".join((*path["nodes"], *path["relations"]))
        plan_id = f"vp-{hashlib.sha256(identity.encode()).hexdigest()[:20]}"
        source_label = str(nodes[source].get("label", source))
        sink_label = str(nodes[sink].get("label", sink))
        steps = (
            ValidationStep(
                1,
                "verify_authority",
                "Confirm the target, method, account, and test window are authorized.",
                "Recorded policy decision and engagement reference.",
                "Stop if any target or action is outside written scope.",
            ),
            ValidationStep(
                2,
                "establish_control",
                f"Confirm control of the test input at {source_label} using owned data only.",
                "A reproducible request or local trace showing input control.",
                "Stop if another user's data or account would be involved.",
            ),
            ValidationStep(
                3,
                "trace_path",
                "Reproduce each reported relationship without expanding beyond the correlated path.",
                "Timestamped evidence for every graph edge.",
                "Stop on an unverified edge, validation barrier, or unexpected target.",
            ),
            ValidationStep(
                4,
                "validate_sink",
                f"Perform the minimum-impact check needed to establish reachability of {sink_label}.",
                "A bounded response, state observation, or controlled callback from owned infrastructure.",
                "Stop before persistence, privilege expansion, data modification, or service degradation.",
                True,
            ),
            ValidationStep(
                5,
                "close_out",
                "Record results, hashes, timestamps, and whether the hypothesis was confirmed.",
                "A redacted evidence bundle and explicit conclusion.",
                "Do not continue testing after sufficient evidence is collected.",
            ),
        )
        plans.append(
            ValidationPlan(
                plan_id,
                source,
                sink,
                float(path["risk_score"]),
                path["confidence"],
                "planned",
                False,
                (
                    "written authorization",
                    "validated engagement policy",
                    "owned test accounts and infrastructure",
                    "evidence storage available",
                ),
                steps,
            )
        )
    return sorted(plans, key=lambda plan: (-plan.risk_score, plan.id))


def render_plans(plans: list[ValidationPlan]) -> str:
    document = {
        "schema_version": 1,
        "execution_allowed": False,
        "summary": {
            "plans": len(plans),
            "approval_required": sum(
                any(step.requires_approval for step in plan.steps) for plan in plans
            ),
        },
        "plans": [plan.to_dict() for plan in plans],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
