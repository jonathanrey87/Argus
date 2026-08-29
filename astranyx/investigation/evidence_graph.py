"""Investigation-wide graph linking findings to their supporting evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePath
from typing import Any


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _finding_base_id(finding: dict[str, Any]) -> str:
    fingerprint = finding.get("fingerprint")
    if (
        isinstance(fingerprint, str)
        and fingerprint.startswith("asx-")
        and not finding.get("fingerprint_collision")
    ):
        return f"finding:{fingerprint}"

    identity = json.dumps(
        {
            "fingerprint": fingerprint,
            "category": finding.get("category"),
            "rule_id": finding.get("rule_id"),
            "file": finding.get("file"),
            "evidence": finding.get("evidence"),
        },
        sort_keys=True,
        default=str,
    )
    return f"finding:identity-{_digest(identity)}"


def build(deduplicated: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic graph from investigation-wide findings."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    id_occurrences: dict[str, int] = {}
    findings = deduplicated.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        base_id = _finding_base_id(finding)
        occurrence = id_occurrences.get(base_id, 0) + 1
        id_occurrences[base_id] = occurrence
        finding_id = base_id if occurrence == 1 else f"{base_id}:{occurrence}"
        nodes[finding_id] = {
            "id": finding_id,
            "type": "finding",
            "fingerprint": finding.get("fingerprint"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
        }

        modules = finding.get("modules", [])
        if isinstance(modules, list):
            for module in sorted({item for item in modules if isinstance(item, str)}):
                module_id = f"module:{module}"
                nodes.setdefault(
                    module_id,
                    {"id": module_id, "type": "module", "name": module},
                )
                edges.add((module_id, finding_id, "reported"))

        file_value = finding.get("file")
        if isinstance(file_value, str) and file_value:
            normalized_file = PurePath(file_value).as_posix()
            file_id = f"file:{_digest(normalized_file.casefold())}"
            nodes.setdefault(
                file_id,
                {"id": file_id, "type": "file", "path": normalized_file},
            )
            edges.add((finding_id, file_id, "located_at"))

        evidence_value = finding.get("evidence")
        if isinstance(evidence_value, str) and evidence_value.strip():
            evidence_id = f"evidence:{_digest(evidence_value)}"
            nodes.setdefault(
                evidence_id,
                {
                    "id": evidence_id,
                    "type": "evidence",
                    "value": evidence_value,
                },
            )
            edges.add((evidence_id, finding_id, "supports"))

    ordered_nodes = [nodes[node_id] for node_id in sorted(nodes)]
    ordered_edges = [
        {"source": source, "target": target, "type": edge_type}
        for source, target, edge_type in sorted(edges)
    ]
    node_types: dict[str, int] = {}
    for node in ordered_nodes:
        node_type = node["type"]
        node_types[node_type] = node_types.get(node_type, 0) + 1

    return {
        "schema_version": 1,
        "summary": {
            "nodes": len(ordered_nodes),
            "edges": len(ordered_edges),
            "node_types": dict(sorted(node_types.items())),
        },
        "nodes": ordered_nodes,
        "edges": ordered_edges,
    }


def write(workspace: Path, deduplicated: dict[str, Any]) -> tuple[Path, dict]:
    """Write the unified evidence graph into an investigation workspace."""
    graph = build(deduplicated)
    output = workspace / "analysis" / "evidence-graph.json"
    output.write_text(json.dumps(graph, indent=2), encoding="utf-8")
    return output, graph
