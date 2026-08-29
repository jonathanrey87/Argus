"""Validated analyzer registry for investigation pipeline extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from astranyx.investigation.manager import InvestigationManager

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")


@dataclass(frozen=True, slots=True)
class AnalyzerContext:
    """Resources made available to an investigation analyzer."""

    target: Path
    workspace: Path
    manager: InvestigationManager
    recursive: bool


@dataclass(frozen=True, slots=True)
class Analyzer:
    """Declarative analyzer plugin contract."""

    name: str
    profiles: tuple[str, ...]
    patterns: tuple[str, ...]
    runner: Callable[[AnalyzerContext], dict]

    def __post_init__(self):
        if not NAME_PATTERN.fullmatch(self.name):
            raise ValueError(f"invalid analyzer name: {self.name!r}")
        if not self.profiles or any(
            not NAME_PATTERN.fullmatch(profile) for profile in self.profiles
        ):
            raise ValueError(f"invalid profiles for analyzer {self.name!r}")
        if not self.patterns or any(
            not isinstance(pattern, str) or not pattern for pattern in self.patterns
        ):
            raise ValueError(f"invalid discovery patterns for analyzer {self.name!r}")
        if not callable(self.runner):
            raise TypeError(f"runner for analyzer {self.name!r} must be callable")

    def supports(self, target: Path, recursive: bool) -> bool:
        for pattern in self.patterns:
            paths = target.rglob(pattern) if recursive else target.glob(pattern)
            if next(paths, None) is not None:
                return True
        return False


class AnalyzerRegistry:
    """Ordered collection of uniquely named analyzer plugins."""

    def __init__(self, analyzers=()):
        self._analyzers: dict[str, Analyzer] = {}
        for analyzer in analyzers:
            self.register(analyzer)

    def register(self, analyzer: Analyzer) -> None:
        if not isinstance(analyzer, Analyzer):
            raise TypeError("analyzer must implement the Analyzer contract")
        if analyzer.name in self._analyzers:
            raise ValueError(f"analyzer already registered: {analyzer.name}")
        self._analyzers[analyzer.name] = analyzer

    def get(self, name: str) -> Analyzer:
        try:
            return self._analyzers[name]
        except KeyError as exc:
            raise ValueError(f"analyzer is not registered: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self._analyzers)

    def profiles(self) -> tuple[str, ...]:
        values = {
            profile
            for analyzer in self._analyzers.values()
            for profile in analyzer.profiles
        }
        return tuple(sorted(values))

    def select(self, target: Path, profile: str, recursive: bool) -> list[str]:
        if profile not in self.profiles():
            choices = ", ".join(self.profiles())
            raise ValueError(f"Unknown profile {profile!r}; choose one of: {choices}")
        return [
            analyzer.name
            for analyzer in self._analyzers.values()
            if profile in analyzer.profiles and analyzer.supports(target, recursive)
        ]

    def run(self, name: str, context: AnalyzerContext) -> dict:
        result = self.get(name).runner(context)
        if not isinstance(result, dict):
            raise TypeError(f"analyzer {name!r} must return a dictionary")
        return result
