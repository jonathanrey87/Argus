import json

import pytest

from astranyx.investigation import orchestrator
from astranyx.investigation.registry import Analyzer, AnalyzerRegistry


def test_registry_validates_and_rejects_duplicate_analyzers():
    analyzer = Analyzer("custom", ("auto", "custom"), ("*.txt",), lambda _ctx: {})
    registry = AnalyzerRegistry((analyzer,))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(analyzer)
    with pytest.raises(ValueError, match="invalid analyzer name"):
        Analyzer("Bad Name", ("auto",), ("*.txt",), lambda _ctx: {})


def test_custom_analyzer_runs_through_sealed_pipeline(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.txt").write_text("authorized input", encoding="utf-8")

    def run_custom(context):
        output = context.workspace / "analysis" / "custom.json"
        output.write_text(json.dumps({"findings": []}), encoding="utf-8")
        return {"files_analyzed": 1, "output_report": str(output)}

    registry = AnalyzerRegistry(
        (Analyzer("custom", ("auto", "custom"), ("*.txt",), run_custom),)
    )
    result = orchestrator.run(
        target,
        profile="custom",
        workspace_root=tmp_path / "investigations",
        analyzer_registry=registry,
    )

    metadata = json.loads((result["workspace"] / "metadata.json").read_text())
    manifest = json.loads((result["workspace"] / "manifest.json").read_text())
    assert result["modules"] == ["custom"]
    assert metadata["modules"][0]["name"] == "custom"
    assert metadata["modules"][0]["status"] == "completed"
    assert manifest["module_results"]["custom"]["files_analyzed"] == 1
    assert any(item["path"] == "analysis/custom.json" for item in manifest["artifacts"])


def test_registry_rejects_non_dictionary_analyzer_result(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.txt").write_text("input", encoding="utf-8")
    registry = AnalyzerRegistry(
        (Analyzer("broken", ("auto",), ("*.txt",), lambda _ctx: None),)
    )

    result = orchestrator.run(
        target,
        analyzer_registry=registry,
        workspace_root=tmp_path / "investigations",
    )

    assert result["status"] == "failed"
    assert result["failures"][0]["error_type"] == "TypeError"
