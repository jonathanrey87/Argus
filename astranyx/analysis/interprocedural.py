"""Bounded, explainable cross-file taint analysis over Astranyx IR."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from astranyx.graph.trust import TrustEngine, TrustLevel
from astranyx.models.ir import IRCall, IRFunction, IRModule, SourceLocation

DEFAULT_SINKS = {
    "eval",
    "exec",
    "include",
    "innerhtml",
    "query",
    "require",
    "system",
    "unserialize",
    "wp_remote_get",
    "wp_remote_post",
}


@dataclass(frozen=True, slots=True)
class FlowStep:
    node: str
    kind: str
    file: str = ""
    line: int = 0
    label: str = ""


@dataclass(slots=True)
class CrossFileTaintEvidence:
    source: str
    sink: str
    path: list[FlowStep]
    files: list[str]
    cross_file: bool
    truncated: bool = False
    validators: list[str] = field(default_factory=list)


class CrossFileTaintEngine:
    """Trace explicit IR flows across calls without guessing assignments."""

    def __init__(
        self,
        *,
        sinks: set[str] | None = None,
        max_depth: int = 24,
        max_paths: int = 1_000,
    ) -> None:
        if max_depth < 1 or max_paths < 1:
            raise ValueError("taint traversal limits must be positive")
        selected_sinks = DEFAULT_SINKS if sinks is None else sinks
        self.sinks = {item.casefold() for item in selected_sinks}
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.trust = TrustEngine()

    @staticmethod
    def _function_id(module: IRModule, function: IRFunction) -> str:
        return f"{module.path}::{function.name}"

    @staticmethod
    def _local(function_id: str, value: str) -> str:
        return f"{function_id}::{value}"

    @staticmethod
    def _return_values(function: IRFunction) -> list[str]:
        values = function.metadata.get("returns", function.metadata.get("return", []))
        if isinstance(values, str):
            return [values]
        if isinstance(values, list):
            return [value for value in values if isinstance(value, str)]
        return []

    @staticmethod
    def _result(call: IRCall) -> str | None:
        value = call.metadata.get("result")
        return value if isinstance(value, str) and value else None

    def _is_sink(self, call: IRCall) -> bool:
        if call.metadata.get("sink") is True:
            return True
        leaf = call.target.rsplit("::", 1)[-1].rsplit(".", 1)[-1].casefold()
        return leaf in self.sinks

    def analyze(self, modules: list[IRModule]) -> list[CrossFileTaintEvidence]:
        functions: dict[str, tuple[IRModule, IRFunction]] = {}
        by_name: dict[str, list[str]] = defaultdict(list)
        for module in modules:
            for function in module.functions:
                function_id = self._function_id(module, function)
                functions[function_id] = (module, function)
                by_name[function.name].append(function_id)

        def resolve(target: str) -> str | None:
            if target in functions:
                return target
            matches = by_name.get(target, [])
            return matches[0] if len(matches) == 1 else None

        edges: dict[str, set[str]] = defaultdict(set)
        steps: dict[str, FlowStep] = {}
        sources: set[str] = set()
        sinks: set[str] = set()
        barriers: set[str] = set()
        validators: dict[str, list[str]] = defaultdict(list)

        def step(node: str, kind: str, location: SourceLocation, label: str) -> None:
            steps.setdefault(
                node,
                FlowStep(node, kind, location.file, location.line, label),
            )

        for function_id, (module, function) in functions.items():
            parameter_locations = {
                parameter: function.location for parameter in function.parameters
            }
            for parameter, location in parameter_locations.items():
                node = self._local(function_id, parameter)
                step(node, "parameter", location, parameter)
                if self.trust.classify(parameter) == TrustLevel.UNTRUSTED:
                    sources.add(node)

            for variable in function.variables:
                node = self._local(function_id, variable.name)
                step(node, "variable", variable.location, variable.name)
                metadata = variable.metadata
                explicit_source = metadata.get("source")
                if (
                    variable.kind == "source" or explicit_source is True
                ) and not isinstance(explicit_source, str):
                    sources.add(node)
                if (
                    self.trust.classify(variable.name.lstrip("$"))
                    == TrustLevel.UNTRUSTED
                ):
                    sources.add(node)
                if isinstance(explicit_source, str):
                    source_node = f"source::{explicit_source}"
                    step(source_node, "source", variable.location, explicit_source)
                    sources.add(source_node)
                    edges[source_node].add(node)
                flows_from = metadata.get("flows_from", [])
                if isinstance(flows_from, str):
                    flows_from = [flows_from]
                if isinstance(flows_from, list):
                    for origin in flows_from:
                        if isinstance(origin, str):
                            edges[self._local(function_id, origin)].add(node)

            for call in function.calls:
                call_node = f"call::{module.path}:{call.location.line}:{function.name}:{call.target}"
                step(call_node, "call", call.location, call.target)
                arguments = [
                    self._local(function_id, argument)
                    for argument in call.arguments
                    if isinstance(argument, str)
                ]
                callee_id = resolve(call.target)
                result = self._result(call)
                result_node = self._local(function_id, result) if result else None

                if callee_id is not None:
                    _, callee = functions[callee_id]
                    for argument, parameter in zip(
                        arguments, callee.parameters, strict=False
                    ):
                        edges[argument].add(self._local(callee_id, parameter))
                    if result_node:
                        step(result_node, "variable", call.location, result)
                        for returned in self._return_values(callee):
                            edges[self._local(callee_id, returned)].add(result_node)
                    is_sanitizer = (
                        call.metadata.get("sanitizer") is True
                        or callee.metadata.get("sanitizer") is True
                    )
                    if is_sanitizer and result_node:
                        barriers.add(result_node)
                        validators[result_node].append(call.target)
                    continue

                for argument in arguments:
                    edges[argument].add(call_node)
                if self._is_sink(call):
                    sinks.add(call_node)
                if result_node:
                    step(result_node, "variable", call.location, result)
                    edges[call_node].add(result_node)
                    if call.metadata.get("sanitizer") is True:
                        barriers.add(result_node)
                        validators[result_node].append(call.target)

        return self._trace(edges, steps, sources, sinks, barriers, validators)

    def _trace(
        self,
        edges: dict[str, set[str]],
        steps: dict[str, FlowStep],
        sources: set[str],
        sinks: set[str],
        barriers: set[str],
        validators: dict[str, list[str]],
    ) -> list[CrossFileTaintEvidence]:
        findings: list[CrossFileTaintEvidence] = []
        examined = 0
        for source in sorted(sources):
            queue = deque([(source, [source])])
            while queue and examined < self.max_paths:
                node, path = queue.popleft()
                examined += 1
                if node in sinks:
                    path_steps = [steps[item] for item in path if item in steps]
                    files = list(
                        dict.fromkeys(item.file for item in path_steps if item.file)
                    )
                    findings.append(
                        CrossFileTaintEvidence(
                            source=steps[source].label,
                            sink=steps[node].label,
                            path=path_steps,
                            files=files,
                            cross_file=len(files) > 1,
                            validators=[
                                validator
                                for item in path
                                for validator in validators.get(item, [])
                            ],
                        )
                    )
                    continue
                if node in barriers or len(path) >= self.max_depth:
                    continue
                for successor in sorted(edges.get(node, set())):
                    if successor not in path:
                        queue.append((successor, [*path, successor]))
        if examined >= self.max_paths:
            for finding in findings:
                finding.truncated = True
        return findings
