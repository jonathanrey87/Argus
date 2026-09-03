"""Conservative PHP-to-IR extraction for interprocedural taint analysis."""

from __future__ import annotations

import re
from pathlib import Path

from astranyx.models.ir import IRCall, IRFunction, IRModule, IRVariable, SourceLocation
from astranyx.wordpress.taint import SOURCES

FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
ASSIGNMENT = re.compile(r"(\$[A-Za-z_]\w*)\s*=\s*(.+?)\s*;")
ASSIGNED_CALL = re.compile(
    r"(\$[A-Za-z_]\w*)\s*=\s*([\\A-Za-z_$][\w\\$]*(?:(?:->|::)[A-Za-z_]\w*)?)\s*\((.*?)\)\s*;"
)
CALL = re.compile(
    r"(?<!function\s)([\\A-Za-z_$][\w\\$]*(?:(?:->|::)[A-Za-z_]\w*)?)\s*\((.*?)\)\s*;"
)
RETURN = re.compile(r"\breturn\s+(\$[A-Za-z_]\w*)\s*;")
VARIABLE = re.compile(r"\$[A-Za-z_]\w*")


def _parameters(raw: str) -> list[str]:
    parameters = []
    for item in raw.split(","):
        matches = VARIABLE.findall(item.split("=", 1)[0])
        if matches:
            parameters.append(matches[-1])
    return parameters


def _arguments(raw: str) -> list[str]:
    return [match for item in raw.split(",") for match in VARIABLE.findall(item)]


def _function_ranges(lines: list[str]) -> list[tuple[str, list[str], int, int]]:
    ranges = []
    index = 0
    while index < len(lines):
        match = FUNCTION.search(lines[index])
        if not match:
            index += 1
            continue
        start = index
        depth = 0
        opened = False
        while index < len(lines):
            depth += lines[index].count("{") - lines[index].count("}")
            opened = opened or "{" in lines[index]
            if opened and depth <= 0:
                break
            index += 1
        end = min(index, len(lines) - 1)
        ranges.append((match.group(1), _parameters(match.group(2)), start, end))
        index += 1
    return ranges


def _parse_function(
    path: str,
    lines: list[str],
    name: str,
    parameters: list[str],
    start: int,
    end: int,
) -> IRFunction:
    function = IRFunction(
        name=name,
        location=SourceLocation(path, start + 1),
        parameters=parameters,
    )
    returns = []
    for index in range(start + 1, end + 1):
        line = lines[index]
        location = SourceLocation(path, index + 1)
        assigned_call = ASSIGNED_CALL.search(line)
        if assigned_call:
            result, target, arguments = assigned_call.groups()
            function.calls.append(
                IRCall(
                    target=target,
                    location=location,
                    arguments=_arguments(arguments),
                    metadata={"result": result},
                )
            )
        else:
            for call in CALL.finditer(line):
                function.calls.append(
                    IRCall(
                        target=call.group(1),
                        location=location,
                        arguments=_arguments(call.group(2)),
                    )
                )

        assignment = ASSIGNMENT.search(line)
        if assignment:
            variable, expression = assignment.groups()
            metadata: dict[str, object] = {}
            source = next(
                (pattern for pattern in SOURCES if re.search(pattern, expression)),
                None,
            )
            if source:
                metadata["source"] = source
            origins = [
                item for item in VARIABLE.findall(expression) if item != variable
            ]
            if origins and not assigned_call:
                metadata["flows_from"] = origins
            function.variables.append(
                IRVariable(
                    name=variable,
                    location=location,
                    kind="source" if source else "local",
                    metadata=metadata,
                )
            )

        returned = RETURN.search(line)
        if returned:
            returns.append(returned.group(1))
    if returns:
        function.metadata["returns"] = returns
    return function


def parse_file(path: Path, *, root: Path | None = None) -> IRModule:
    """Extract only explicit functions, assignments, calls, and returns."""
    resolved = path.resolve()
    module_path = str(resolved.relative_to(root.resolve())) if root else str(resolved)
    lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
    module = IRModule(path=module_path, language="php")
    for name, parameters, start, end in _function_ranges(lines):
        module.functions.append(
            _parse_function(module_path, lines, name, parameters, start, end)
        )
    return module
