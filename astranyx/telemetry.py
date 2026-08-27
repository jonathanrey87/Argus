"""Small OpenTelemetry compatibility layer used by Astranyx modules.

Astranyx records spans when OpenTelemetry is installed. Static analysis and the
command-line interface remain usable without the optional tracing stack.
"""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
from enum import Enum
from typing import Any

try:
    from opentelemetry import trace as _backend_trace
    from opentelemetry.trace import Status, StatusCode
except ImportError:

    class StatusCode(Enum):
        """Fallback values matching the OpenTelemetry status names."""

        UNSET = 0
        OK = 1
        ERROR = 2

    class Status:
        """Fallback span status used when OpenTelemetry is unavailable."""

        def __init__(
            self,
            status_code: StatusCode = StatusCode.UNSET,
            description: str | None = None,
        ) -> None:
            self.status_code = status_code
            self.description = description

    class _NoOpSpan:
        def set_attribute(self, _name: str, _value: Any) -> None:
            return None

        def set_status(self, _status: Status) -> None:
            return None

        def record_exception(self, _exception: BaseException) -> None:
            return None

    class _NoOpTracer:
        def start_as_current_span(self, _name: str):
            return nullcontext(_NoOpSpan())

    class _NoOpTrace:
        @staticmethod
        def get_tracer(_name: str) -> _NoOpTracer:
            return _NoOpTracer()

    _backend_trace = _NoOpTrace()


SAFE_ATTRIBUTES = {
    "astranyx.command",
    "astranyx.investigation.profile",
    "astranyx.javascript.files_discovered",
    "astranyx.javascript.files_failed",
    "astranyx.javascript.files_processed",
    "astranyx.javascript.files_with_findings",
    "astranyx.javascript.findings_total",
    "astranyx.javascript.recursive",
    "astranyx.javascript.routes_unique",
    "astranyx.subcommand",
    "astranyx.trace.enabled",
    "astranyx.workspace.directories",
}


class _PrivacySafeSpan:
    """Allow only aggregate, non-identifying telemetry fields."""

    def __init__(self, span: Any) -> None:
        self._span = span

    def set_attribute(self, name: str, value: Any) -> None:
        if name in SAFE_ATTRIBUTES:
            self._span.set_attribute(name, value)

    def set_status(self, status: Status) -> None:
        status_code = getattr(status, "status_code", StatusCode.UNSET)
        self._span.set_status(Status(status_code))

    def record_exception(self, _exception: BaseException) -> None:
        # Exception messages frequently contain customer paths or source details.
        return None


class _PrivacySafeTracer:
    def __init__(self, tracer: Any) -> None:
        self._tracer = tracer

    @contextmanager
    def start_as_current_span(self, name: str):
        with self._tracer.start_as_current_span(name) as span:
            yield _PrivacySafeSpan(span)


class _PrivacySafeTrace:
    """No-op by default; explicitly enabled after telemetry registration."""

    def __init__(self) -> None:
        self._enabled = False

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def get_tracer(self, name: str):
        if not self._enabled:
            return _NoOpTracer()
        return _PrivacySafeTracer(_backend_trace.get_tracer(name))


trace = _PrivacySafeTrace()
