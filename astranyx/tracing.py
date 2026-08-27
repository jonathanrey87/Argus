import os

from astranyx.telemetry import trace

try:
    from arize.otel import register
except ImportError:
    register = None


def configure_tracing():
    """Configure privacy-filtered tracing only after explicit opt-in."""
    enabled = os.getenv("ASTRANYX_TELEMETRY", "").casefold() in {
        "1",
        "true",
        "yes",
    }
    if not enabled:
        trace.disable()
        return None

    space_id = os.getenv("ARIZE_SPACE_ID")
    api_key = os.getenv("ARIZE_API_KEY")

    if not space_id or not api_key:
        return None

    if register is None:
        return None

    register(
        space_id=space_id,
        api_key=api_key,
        project_name="astranyx",
    )

    trace.enable()
    return trace.get_tracer("astranyx")
