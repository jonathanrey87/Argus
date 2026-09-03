"""Bounded JSON reporting for attack-surface graphs and correlated paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from astranyx.graph.attack_surface import AttackPathCorrelator, AttackSurfaceGraph

MAX_GRAPH_INPUT_BYTES = 67_108_864


def load_graph(path: str | Path) -> AttackSurfaceGraph:
    source = Path(path).expanduser()
    try:
        if source.stat().st_size > MAX_GRAPH_INPUT_BYTES:
            raise ValueError("attack-surface input exceeds 64 MiB")
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load attack-surface graph: {exc}") from exc
    if isinstance(document, dict) and "graph" in document:
        document = document["graph"]
    try:
        return AttackSurfaceGraph.from_dict(document)
    except TypeError as exc:
        raise ValueError(str(exc)) from exc


def build_report(
    graph: AttackSurfaceGraph,
    *,
    max_depth: int = 16,
    max_paths: int = 1_000,
    max_states: int = 100_000,
) -> dict[str, Any]:
    correlator = AttackPathCorrelator(
        max_depth=max_depth,
        max_paths=max_paths,
        max_states=max_states,
    )
    paths = correlator.correlate(graph)
    return {
        "schema_version": 1,
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "attack_paths": len(paths),
            "truncated": correlator.last_truncated,
        },
        "graph": graph.to_dict(),
        "attack_paths": [path.to_dict() for path in paths],
    }


def render_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"
