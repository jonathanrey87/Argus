"""Analysis-pipeline integration for attack-surface correlation."""

from __future__ import annotations

from astranyx.analysis.pipeline import AnalysisStage
from astranyx.core.finding import Finding
from astranyx.graph.attack_surface import AttackSurfaceGraph
from astranyx.graph.reporting import build_report


class AttackSurfaceStage(AnalysisStage):
    """Build graph outputs from normalized findings and explicit taint evidence."""

    name = "attack_surface"

    def __init__(
        self,
        *,
        findings_key: str = "findings",
        taint_key: str = "cross_file_taint",
        graph_key: str = "attack_surface_graph",
        report_key: str = "attack_path_report",
        max_depth: int = 16,
        max_paths: int = 1_000,
        max_states: int = 100_000,
    ):
        self.findings_key = findings_key
        self.taint_key = taint_key
        self.graph_key = graph_key
        self.report_key = report_key
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_states = max_states

    def run(self, context: dict) -> None:
        findings = context.get(self.findings_key, [])
        if not isinstance(findings, list) or not all(
            isinstance(finding, Finding) for finding in findings
        ):
            raise TypeError(
                "attack-surface findings must be normalized Finding objects"
            )
        taint = context.get(self.taint_key, [])
        if not isinstance(taint, list):
            raise TypeError("cross-file taint evidence must be a list")
        graph = AttackSurfaceGraph.from_findings(findings)
        graph.add_taint_evidence(taint)
        context[self.graph_key] = graph
        context[self.report_key] = build_report(
            graph,
            max_depth=self.max_depth,
            max_paths=self.max_paths,
            max_states=self.max_states,
        )
