"""Evidence-backed attack-surface graph and bounded path correlation."""

from __future__ import annotations

import hashlib
from collections import deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from astranyx.core.finding import Finding

SOURCE_KINDS = frozenset({"entrypoint", "external_asset", "untrusted_input"})
SINK_KINDS = frozenset(
    {"data_store", "privileged_action", "security_sink", "sensitive_asset"}
)
FLOW_RELATIONS = frozenset({"calls", "flows_to", "reaches", "returns"})
BARRIER_KINDS = frozenset({"authorization", "sanitizer", "validation"})
SEVERITY_WEIGHT = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


@dataclass(slots=True)
class SurfaceNode:
    id: str
    kind: str
    label: str
    file: str = ""
    line: int = 0
    trust: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id or len(self.id) > 512:
            raise ValueError("surface node ID must be between 1 and 512 characters")
        if not self.kind or not self.label:
            raise ValueError("surface nodes require kind and label")
        if self.line < 0:
            raise ValueError("surface node line cannot be negative")


@dataclass(slots=True)
class SurfaceEdge:
    source: str
    target: str
    relation: str
    evidence: str
    confidence: int = 50
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source or not self.target or not self.relation:
            raise ValueError("surface edges require source, target, and relation")
        if not self.evidence.strip():
            raise ValueError("surface edges require explicit evidence")
        if not 0 <= self.confidence <= 100:
            raise ValueError("edge confidence must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class AttackPath:
    source: str
    sink: str
    nodes: tuple[str, ...]
    relations: tuple[str, ...]
    evidence: tuple[str, ...]
    confidence: int
    risk_score: float
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackSurfaceGraph:
    """A deterministic graph that refuses dangling or unevidenced relationships."""

    def __init__(self, *, max_nodes: int = 100_000, max_edges: int = 500_000):
        if max_nodes < 1 or max_edges < 1:
            raise ValueError("graph bounds must be positive")
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.nodes: dict[str, SurfaceNode] = {}
        self.edges: dict[tuple[str, str, str], SurfaceEdge] = {}
        self._successors: dict[str, set[tuple[str, str, str]]] = {}

    def add_node(self, node: SurfaceNode) -> None:
        existing = self.nodes.get(node.id)
        if existing is not None and existing != node:
            raise ValueError(f"conflicting surface node ID: {node.id}")
        if existing is None and len(self.nodes) >= self.max_nodes:
            raise ValueError("attack-surface node bound exceeded")
        self.nodes[node.id] = node

    def add_edge(self, edge: SurfaceEdge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError("surface edge endpoints must exist before the edge")
        key = (edge.source, edge.target, edge.relation)
        existing = self.edges.get(key)
        if existing is not None and existing != edge:
            raise ValueError("conflicting evidence for duplicate surface edge")
        if existing is None:
            if len(self.edges) >= self.max_edges:
                raise ValueError("attack-surface edge bound exceeded")
            self.edges[key] = edge
            self._successors.setdefault(edge.source, set()).add(key)

    def successors(
        self, node_id: str, *, relations: set[str] | None = None
    ) -> list[SurfaceEdge]:
        selected = [self.edges[key] for key in self._successors.get(node_id, set())]
        if relations is not None:
            selected = [edge for edge in selected if edge.relation in relations]
        return sorted(
            selected, key=lambda edge: (edge.target, edge.relation, edge.evidence)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "nodes": [asdict(self.nodes[key]) for key in sorted(self.nodes)],
            "edges": [asdict(self.edges[key]) for key in sorted(self.edges)],
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> AttackSurfaceGraph:
        """Load a versioned graph document through the normal validation gates."""
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            raise ValueError("unsupported or malformed attack-surface graph")
        raw_nodes = document.get("nodes")
        raw_edges = document.get("edges")
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise TypeError("attack-surface graph requires node and edge lists")
        graph = cls()
        try:
            for value in raw_nodes:
                graph.add_node(SurfaceNode(**value))
            for value in raw_edges:
                graph.add_edge(SurfaceEdge(**value))
        except (TypeError, AttributeError) as exc:
            raise ValueError("malformed attack-surface node or edge") from exc
        return graph

    @staticmethod
    def _flow_node_id(value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
        return f"flow::{digest}"

    def add_taint_evidence(self, evidence_items: Iterable[Any]) -> None:
        """Add validated cross-file taint paths without re-inferring their flow."""
        for evidence in evidence_items:
            steps = list(getattr(evidence, "path", ()))
            if len(steps) < 2:
                continue
            identifiers = [self._flow_node_id(str(step.node)) for step in steps]
            for index, (identifier, step) in enumerate(
                zip(identifiers, steps, strict=True)
            ):
                kind = "operation"
                trust = "unknown"
                if index == 0:
                    kind = "untrusted_input"
                    trust = "untrusted"
                elif index == len(steps) - 1:
                    kind = "security_sink"
                node = SurfaceNode(
                    identifier,
                    kind,
                    str(step.label or step.node),
                    file=str(step.file),
                    line=int(step.line),
                    trust=trust,
                    metadata={"flow_node": str(step.node), "flow_kind": str(step.kind)},
                )
                existing = self.nodes.get(identifier)
                if existing is None:
                    self.add_node(node)
                elif kind in SOURCE_KINDS:
                    existing.kind = kind
                    existing.trust = trust
                elif kind in SINK_KINDS and existing.kind not in SOURCE_KINDS:
                    existing.kind = kind
            for left, right, step in zip(
                identifiers[:-1], identifiers[1:], steps[1:], strict=True
            ):
                location = (
                    f"{step.file}:{step.line}" if step.file else "explicit taint trace"
                )
                self.add_edge(
                    SurfaceEdge(
                        left,
                        right,
                        "flows_to",
                        f"{step.label} at {location}",
                        90,
                        {"analyzer": "cross-file-taint"},
                    )
                )

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> AttackSurfaceGraph:
        """Index findings structurally without inventing exploit-flow edges."""
        graph = cls()
        for finding in sorted(findings, key=lambda item: item.fingerprint):
            file_id = f"file::{finding.file}"
            graph.add_node(
                SurfaceNode(file_id, "component", finding.file, file=finding.file)
            )
            finding_id = f"finding::{finding.fingerprint}"
            graph.add_node(
                SurfaceNode(
                    finding_id,
                    "finding",
                    finding.category,
                    file=finding.file,
                    line=finding.line,
                    metadata={
                        "fingerprint": finding.fingerprint,
                        "severity": finding.severity.casefold(),
                        "confidence": finding.confidence,
                        "review_state": finding.review_state,
                    },
                )
            )
            graph.add_edge(
                SurfaceEdge(
                    file_id,
                    finding_id,
                    "contains",
                    finding.evidence,
                    finding.confidence,
                )
            )
        return graph


class AttackPathCorrelator:
    """Trace explicit source-to-sink relationships with strict traversal bounds."""

    def __init__(
        self,
        *,
        max_depth: int = 16,
        max_paths: int = 1_000,
        max_states: int = 100_000,
        allowed_relations: set[str] | None = None,
    ):
        if not 1 <= max_depth <= 256:
            raise ValueError("max_depth must be between 1 and 256")
        if not 1 <= max_paths <= 100_000:
            raise ValueError("max_paths must be between 1 and 100000")
        if not 1 <= max_states <= 10_000_000:
            raise ValueError("max_states must be between 1 and 10000000")
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_states = max_states
        self.allowed_relations = frozenset(allowed_relations or FLOW_RELATIONS)
        self.last_truncated = False

    def correlate(self, graph: AttackSurfaceGraph) -> list[AttackPath]:
        paths: list[AttackPath] = []
        examined = 0
        truncated = False
        sources = sorted(
            node.id for node in graph.nodes.values() if node.kind in SOURCE_KINDS
        )
        for source in sources:
            queue = deque([(source, (source,), (), ())])
            while queue:
                if len(paths) >= self.max_paths or examined >= self.max_states:
                    truncated = True
                    break
                node_id, node_path, relations, evidence = queue.popleft()
                examined += 1
                node = graph.nodes[node_id]
                if node_id != source and node.kind in SINK_KINDS:
                    confidence = min(
                        graph.edges[(left, right, relation)].confidence
                        for left, right, relation in zip(
                            node_path[:-1], node_path[1:], relations, strict=True
                        )
                    )
                    severity = SEVERITY_WEIGHT.get(
                        str(node.metadata.get("severity", "medium")).casefold(), 3
                    )
                    paths.append(
                        AttackPath(
                            source,
                            node_id,
                            node_path,
                            relations,
                            evidence,
                            confidence,
                            round(severity * confidence / 100, 2),
                        )
                    )
                    continue
                if node_id != source and node.kind in BARRIER_KINDS:
                    continue
                if len(node_path) - 1 >= self.max_depth:
                    continue
                for edge in graph.successors(
                    node_id, relations=set(self.allowed_relations)
                ):
                    if edge.target not in node_path:
                        queue.append(
                            (
                                edge.target,
                                (*node_path, edge.target),
                                (*relations, edge.relation),
                                (*evidence, edge.evidence),
                            )
                        )
            if truncated:
                break
        if truncated:
            paths = [
                AttackPath(
                    path.source,
                    path.sink,
                    path.nodes,
                    path.relations,
                    path.evidence,
                    path.confidence,
                    path.risk_score,
                    True,
                )
                for path in paths
            ]
        self.last_truncated = truncated
        return sorted(
            paths,
            key=lambda path: (-path.risk_score, path.source, path.sink, path.nodes),
        )
