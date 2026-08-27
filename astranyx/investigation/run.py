import json
from datetime import UTC, datetime
from pathlib import Path

from astranyx import __version__
from astranyx.telemetry import Status, StatusCode, trace

tracer = trace.get_tracer("astranyx.investigation")


def _unique_workspace_root(
    parent: Path,
    investigation_id: str,
) -> Path:
    """Return a workspace path that does not already exist."""
    root = parent / investigation_id
    suffix = 1

    while root.exists():
        root = parent / (f"{investigation_id}-{suffix:02d}")
        suffix += 1

    return root


def run(args):
    """Create a new Astranyx investigation workspace."""
    analyst = getattr(
        args,
        "analyst",
        None,
    )
    target = getattr(args, "target", None)
    trace_enabled = bool(getattr(args, "trace_enabled", False))
    workspace_parent = Path(
        getattr(args, "workspace_root", "investigations")
    ).expanduser()

    with tracer.start_as_current_span("astranyx.investigation.create") as span:
        timestamp = datetime.now(UTC)

        base_id = timestamp.strftime("INV-%Y%m%d-%H%M%S")
        root = _unique_workspace_root(
            workspace_parent,
            base_id,
        )
        investigation_id = root.name

        directories = (
            "analysis",
            "api",
            "evidence",
            "html",
            "js",
            "logs",
            "notes",
            "reports",
            "screenshots",
        )

        try:
            for directory in directories:
                (root / directory).mkdir(
                    parents=True,
                    exist_ok=True,
                )

            metadata = {
                "id": investigation_id,
                "created": timestamp.isoformat(),
                "status": "created",
                "target": target,
                "analyst": analyst or "unspecified",
                "astranyx_version": __version__,
                "trace_enabled": trace_enabled,
                "modules": [],
                "findings": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
            }

            metadata_path = root / "metadata.json"

            metadata_path.write_text(
                json.dumps(metadata, indent=2),
                encoding="utf-8",
            )

            span.set_attribute(
                "astranyx.investigation.id",
                investigation_id,
            )
            span.set_attribute(
                "astranyx.metadata.file",
                str(metadata_path),
            )
            span.set_attribute(
                "astranyx.workspace.directories",
                len(directories),
            )
            span.set_attribute(
                "astranyx.trace.enabled",
                trace_enabled,
            )

            if target:
                span.set_attribute(
                    "astranyx.target",
                    str(target),
                )

            span.set_status(Status(StatusCode.OK))

            print("[+] Investigation created")
            print(f"    ID: {investigation_id}")
            print(f"    Path: {root}")
            print(f"    Metadata: {metadata_path}")

            return root

        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
