import json
import sys

import pytest

from astranyx.cli import main
from astranyx.graph import AttackSurfaceGraph, SurfaceEdge, SurfaceNode, build_report
from astranyx.validation.playbook import (
    generate_plans,
    load_attack_path_report,
    render_plans,
)


def report():
    graph = AttackSurfaceGraph()
    graph.add_node(SurfaceNode("input", "untrusted_input", "request.url"))
    graph.add_node(
        SurfaceNode(
            "sink", "security_sink", "HTTP client", metadata={"severity": "high"}
        )
    )
    graph.add_edge(SurfaceEdge("input", "sink", "flows_to", "argument trace", 85))
    return build_report(graph)


def test_generated_plan_is_non_executing_and_approval_gated():
    plans = generate_plans(report())
    assert len(plans) == 1
    assert plans[0].execution_allowed is False
    assert plans[0].status == "planned"
    assert any(step.requires_approval for step in plans[0].steps)
    assert "service degradation" in plans[0].steps[3].stop_condition


def test_plan_ids_and_rendering_are_deterministic():
    first = render_plans(generate_plans(report()))
    second = render_plans(generate_plans(report()))
    assert first == second
    assert json.loads(first)["execution_allowed"] is False


def test_rejects_path_referencing_unknown_node():
    document = report()
    document["attack_paths"][0]["nodes"] = ["input", "missing"]
    with pytest.raises(ValueError, match="unknown"):
        generate_plans(document)


def test_rejects_path_relationship_not_backed_by_graph():
    document = report()
    document["attack_paths"][0]["relations"] = ["calls"]
    with pytest.raises(ValueError, match="absent from the graph"):
        generate_plans(document)


def test_cli_generates_validation_plan(tmp_path, monkeypatch, capsys):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["astranyx", "validation", "plan", str(source)])
    main()
    document = json.loads(capsys.readouterr().out)
    assert document["summary"] == {"plans": 1, "approval_required": 1}
    assert document["plans"][0]["execution_allowed"] is False


def test_loader_accepts_only_versioned_report(tmp_path):
    source = tmp_path / "report.json"
    source.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        load_attack_path_report(source)
