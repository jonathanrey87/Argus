import json
import sys

import pytest

from astranyx.analysis.attack_surface import AttackSurfaceStage
from astranyx.analysis.interprocedural import CrossFileTaintEvidence, FlowStep
from astranyx.cli import main
from astranyx.graph import AttackSurfaceGraph
from astranyx.graph.reporting import build_report, load_graph


def taint_evidence():
    return CrossFileTaintEvidence(
        source="request.url",
        sink="wp_remote_get",
        path=[
            FlowStep(
                "controller::request.url",
                "parameter",
                "controller.php",
                10,
                "request.url",
            ),
            FlowStep("service::$url", "parameter", "service.php", 20, "$url"),
            FlowStep("call::wp_remote_get", "call", "service.php", 22, "wp_remote_get"),
        ],
        files=["controller.php", "service.php"],
        cross_file=True,
    )


def test_taint_adapter_produces_explicit_correlated_path():
    graph = AttackSurfaceGraph()
    graph.add_taint_evidence([taint_evidence()])
    report = build_report(graph)
    assert report["summary"] == {
        "nodes": 3,
        "edges": 2,
        "attack_paths": 1,
        "truncated": False,
    }
    path = report["attack_paths"][0]
    assert path["confidence"] == 90
    assert path["evidence"][-1] == "wp_remote_get at service.php:22"


def test_graph_round_trip_revalidates_nodes_and_edges(tmp_path):
    graph = AttackSurfaceGraph()
    graph.add_taint_evidence([taint_evidence()])
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph.to_dict()), encoding="utf-8")
    loaded = load_graph(path)
    assert loaded.to_dict() == graph.to_dict()


def test_graph_loader_rejects_dangling_edge(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "nodes": [],
                "edges": [
                    {
                        "source": "a",
                        "target": "b",
                        "relation": "flows_to",
                        "evidence": "claim",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="endpoints"):
        load_graph(path)


def test_cli_correlate_emits_versioned_report(tmp_path, monkeypatch, capsys):
    graph = AttackSurfaceGraph()
    graph.add_taint_evidence([taint_evidence()])
    source = tmp_path / "graph.json"
    source.write_text(json.dumps(graph.to_dict()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["astranyx", "graph", "correlate", str(source)])
    main()
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert report["summary"]["attack_paths"] == 1


@pytest.mark.parametrize("value", ["0", "257"])
def test_cli_rejects_invalid_traversal_bounds(tmp_path, monkeypatch, value):
    source = tmp_path / "graph.json"
    source.write_text(json.dumps(AttackSurfaceGraph().to_dict()), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["astranyx", "graph", "correlate", str(source), "--max-depth", value],
    )
    with pytest.raises(SystemExit, match="max_depth"):
        main()


def test_pipeline_stage_wires_taint_evidence_into_report():
    context = {"findings": [], "cross_file_taint": [taint_evidence()]}
    AttackSurfaceStage().run(context)
    assert context["attack_path_report"]["summary"]["attack_paths"] == 1
    assert len(context["attack_surface_graph"].edges) == 2


def test_pipeline_stage_rejects_untyped_finding_data():
    with pytest.raises(TypeError, match="normalized Finding"):
        AttackSurfaceStage().run({"findings": [{}]})
