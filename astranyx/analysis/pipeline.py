from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisResult:
    findings: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AnalysisStage:
    """Base class for all Astranyx analysis stages."""

    name = "stage"

    def run(self, context: dict) -> None:
        raise NotImplementedError


class AnalysisPipeline:
    """Executes registered analysis stages in order."""

    def __init__(self):
        self.stages: list[AnalysisStage] = []

    def register(self, stage: AnalysisStage) -> None:
        self.stages.append(stage)

    def execute(self, context: dict) -> dict:
        for stage in self.stages:
            stage.run(context)

        return context


def build_default_pipeline() -> AnalysisPipeline:
    """
    Builds the default Astranyx analysis pipeline.

    The local import avoids a circular import because EvidenceGateStage
    inherits from AnalysisStage.
    """
    from astranyx.analysis.attack_surface import AttackSurfaceStage
    from astranyx.analysis.evidence_gate import EvidenceGateStage

    pipeline = AnalysisPipeline()
    pipeline.register(EvidenceGateStage())
    pipeline.register(AttackSurfaceStage())

    return pipeline
