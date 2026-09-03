from astranyx.analysis.pipeline import (
    AnalysisPipeline,
    AnalysisStage,
    build_default_pipeline,
)


class DummyStage(AnalysisStage):
    name = "dummy"

    def run(self, context):
        context["ran"] = True


def test_pipeline():
    pipeline = AnalysisPipeline()
    pipeline.register(DummyStage())

    context = {}
    result = pipeline.execute(context)

    assert result["ran"] is True


def test_default_pipeline_registers_evidence_gate():
    pipeline = build_default_pipeline()

    assert [stage.name for stage in pipeline.stages] == [
        "evidence_gate",
        "attack_surface",
    ]


def test_default_pipeline_evaluates_findings():
    pipeline = build_default_pipeline()

    result = pipeline.execute(
        {
            "finding_evidence": [
                {
                    "category": "graphql",
                    "protected_data": False,
                },
                {
                    "category": "http_500",
                    "data_exposure": True,
                },
            ]
        }
    )

    assert len(result["evidence_decisions"]) == 2
    assert result["reportable_findings"] == 1
    assert result["attack_path_report"]["summary"] == {
        "nodes": 0,
        "edges": 0,
        "attack_paths": 0,
        "truncated": False,
    }
