import pytest

from astranyx.core.finding import Finding
from astranyx.graph.attack_surface import (
    AttackPathCorrelator,
    AttackSurfaceGraph,
    SurfaceEdge,
    SurfaceNode,
)


def build_path_graph():
    graph = AttackSurfaceGraph()
    graph.add_node(SurfaceNode("http", "entrypoint", "POST /import", trust="untrusted"))
    graph.add_node(SurfaceNode("url", "untrusted_input", "body.url", trust="untrusted"))
    graph.add_node(
        SurfaceNode(
            "fetch", "security_sink", "HTTP client", metadata={"severity": "high"}
        )
    )
    graph.add_edge(SurfaceEdge("http", "url", "flows_to", "route binds body.url", 90))
    graph.add_edge(
        SurfaceEdge("url", "fetch", "flows_to", "url passed to HTTP client", 80)
    )
    return graph


def test_correlates_explicit_explainable_source_to_sink_path():
    paths = AttackPathCorrelator().correlate(build_path_graph())
    assert len(paths) == 2
    direct = next(path for path in paths if path.source == "http")
    assert direct.nodes == ("http", "url", "fetch")
    assert direct.evidence == ("route binds body.url", "url passed to HTTP client")
    assert direct.confidence == 80
    assert direct.risk_score == 3.2


def test_structural_contains_edge_does_not_become_attack_path():
    finding = Finding(
        "SSRF Sink", "high", "api.py", "/src/api.py", 20, "client.get(url)", "review"
    )
    graph = AttackSurfaceGraph.from_findings([finding])
    graph.nodes["file::api.py"].kind = "entrypoint"
    graph.nodes[f"finding::{finding.fingerprint}"].kind = "security_sink"
    assert AttackPathCorrelator().correlate(graph) == []


def test_validation_barrier_stops_correlation():
    graph = build_path_graph()
    graph.add_node(SurfaceNode("allowlist", "validation", "URL allowlist"))
    graph.edges.clear()
    graph._successors.clear()
    graph.add_edge(SurfaceEdge("url", "allowlist", "flows_to", "validated", 100))
    graph.add_edge(SurfaceEdge("allowlist", "fetch", "flows_to", "approved URL", 100))
    assert AttackPathCorrelator().correlate(graph) == []


def test_cycles_are_bounded_and_paths_are_deterministic():
    graph = build_path_graph()
    graph.add_edge(SurfaceEdge("url", "http", "returns", "retry loop", 70))
    first = AttackPathCorrelator().correlate(graph)
    second = AttackPathCorrelator().correlate(graph)
    assert first == second
    assert all(len(path.nodes) <= 3 for path in first)


def test_path_limit_marks_results_truncated():
    graph = AttackSurfaceGraph()
    graph.add_node(SurfaceNode("source", "entrypoint", "input"))
    for index in range(3):
        sink = f"sink-{index}"
        graph.add_node(SurfaceNode(sink, "security_sink", sink))
        graph.add_edge(SurfaceEdge("source", sink, "reaches", f"edge {index}"))
    paths = AttackPathCorrelator(max_paths=2).correlate(graph)
    assert len(paths) == 2
    assert all(path.truncated for path in paths)


def test_state_limit_bounds_branching_graph_without_a_sink():
    graph = AttackSurfaceGraph()
    graph.add_node(SurfaceNode("source", "entrypoint", "input"))
    previous = ["source"]
    for depth in range(5):
        current = []
        for parent in previous:
            for branch in range(3):
                node_id = f"{parent}-{depth}-{branch}"
                graph.add_node(SurfaceNode(node_id, "operation", node_id))
                graph.add_edge(SurfaceEdge(parent, node_id, "flows_to", node_id))
                current.append(node_id)
        previous = current
    correlator = AttackPathCorrelator(max_states=10)
    assert correlator.correlate(graph) == []
    assert correlator.last_truncated


def test_rejects_dangling_unevidenced_and_invalid_edges():
    graph = AttackSurfaceGraph()
    graph.add_node(SurfaceNode("one", "component", "one"))
    with pytest.raises(ValueError, match="endpoints"):
        graph.add_edge(SurfaceEdge("one", "missing", "calls", "callsite"))
    with pytest.raises(ValueError, match="evidence"):
        SurfaceEdge("one", "one", "calls", "")
    with pytest.raises(ValueError, match="confidence"):
        SurfaceEdge("one", "one", "calls", "callsite", 101)
