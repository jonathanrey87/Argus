"""End-to-end orchestration for local, authorized Astranyx investigations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace

from astranyx.investigation.manager import InvestigationManager
from astranyx.investigation.run import run as create_workspace
from astranyx.modules import js
from astranyx.wordpress import scanner

SUPPORTED_PROFILES = ("auto", "web", "javascript", "wordpress")


def _contains(target: Path, pattern: str, recursive: bool) -> bool:
    paths = target.rglob(pattern) if recursive else target.glob(pattern)
    return next(paths, None) is not None


def select_modules(
    target: str | Path,
    profile: str = "auto",
    recursive: bool = True,
) -> list[str]:
    """Select compatible analyzers for a local target and profile."""
    path = Path(target).expanduser().resolve()

    if profile not in SUPPORTED_PROFILES:
        choices = ", ".join(SUPPORTED_PROFILES)
        raise ValueError(f"Unknown profile {profile!r}; choose one of: {choices}")

    if not path.exists():
        raise FileNotFoundError(path)

    if not path.is_dir():
        raise NotADirectoryError(path)

    has_javascript = _contains(path, "*.js", recursive)
    has_php = _contains(path, "*.php", recursive)

    if profile == "javascript":
        modules = ["javascript"] if has_javascript else []
    elif profile == "wordpress":
        modules = ["wordpress"] if has_php else []
    else:
        modules = []
        if has_javascript:
            modules.append("javascript")
        if has_php:
            modules.append("wordpress")

    if not modules:
        raise ValueError(
            f"No analyzable JavaScript or PHP files found in {path} "
            f"for profile {profile!r}"
        )

    return modules


def _run_javascript(
    target: Path,
    workspace: Path,
    recursive: bool,
) -> dict:
    output = workspace / "analysis" / "javascript.json"
    report = js.analyze(
        target,
        output=output,
        investigation=workspace,
        recursive=recursive,
    )

    return {
        "files_analyzed": report["files_analyzed"],
        "routes": len(report["routes"]),
        "output_report": str(output),
    }


def _run_wordpress(
    target: Path,
    workspace: Path,
    manager: InvestigationManager,
    recursive: bool,
) -> dict:
    started = perf_counter()
    output = workspace / "reports" / "wordpress"
    report = scanner.run(
        target,
        output=output,
        recursive=recursive,
    )
    duration_ms = round((perf_counter() - started) * 1000, 2)

    manager.load()
    manager.add_module(
        "wordpress",
        duration_ms=duration_ms,
        details={
            "findings_total": report["findings_total"],
            "finding_categories": len(report["categories"]),
            "source_path": str(target),
            "output_directory": str(output),
        },
    )
    manager.update_findings(**report["severity"])

    return {
        "findings_total": report["findings_total"],
        "categories": report["categories"],
        "output_directory": str(output),
    }


def _artifact_record(path: Path, workspace: Path) -> dict:
    content = path.read_bytes()
    return {
        "path": path.relative_to(workspace).as_posix(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _collect_artifacts(workspace: Path) -> list[dict]:
    excluded = {"manifest.json", "metadata.json"}
    return [
        _artifact_record(path, workspace)
        for path in sorted(workspace.rglob("*"))
        if path.is_file() and path.name not in excluded
    ]


def _write_manifest(
    workspace: Path,
    manager: InvestigationManager,
    module_results: dict,
    failures: list[dict],
) -> Path:
    artifacts = _collect_artifacts(workspace)
    manager.set_artifacts(artifacts)
    manager.load()

    manifest = {
        "schema_version": 1,
        "investigation": {
            "id": manager.data["id"],
            "status": manager.data["status"],
            "target": manager.data["target"],
            "profile": manager.data["profile"],
            "selected_modules": manager.data["selected_modules"],
            "created": manager.data["created"],
            "completed": manager.data.get("completed"),
        },
        "module_results": module_results,
        "failures": failures,
        "artifacts": artifacts,
    }

    manifest_path = workspace / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return manifest_path


def run(
    target: str | Path,
    *,
    analyst: str = "unspecified",
    profile: str = "auto",
    recursive: bool = True,
    trace_enabled: bool = False,
    workspace_root: str | Path = "investigations",
) -> dict:
    """Create a workspace, run selected analyzers, and seal a manifest."""
    target_path = Path(target).expanduser().resolve()
    modules = select_modules(target_path, profile, recursive)

    workspace_args = SimpleNamespace(
        analyst=analyst,
        target=str(target_path),
        trace_enabled=trace_enabled,
        workspace_root=workspace_root,
    )
    workspace = create_workspace(workspace_args)
    manager = InvestigationManager(workspace)
    manager.set_context(profile, modules)
    manager.set_status("active")

    module_results = {}
    failures = []

    for module in modules:
        try:
            if module == "javascript":
                module_results[module] = _run_javascript(
                    target_path,
                    workspace,
                    recursive,
                )
            elif module == "wordpress":
                module_results[module] = _run_wordpress(
                    target_path,
                    workspace,
                    manager,
                    recursive,
                )
        except Exception as exc:  # noqa: BLE001 - analyzer boundary isolation
            failure = {
                "module": module,
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
            failures.append(failure)
            manager.load()
            manager.add_module(
                module,
                status="failed",
                details={"error": failure},
            )

    if not failures:
        status = "completed"
    elif module_results:
        status = "partial"
    else:
        status = "failed"

    manager.load()
    manager.finish_with_status(status)
    manifest_path = _write_manifest(
        workspace,
        manager,
        module_results,
        failures,
    )

    print()
    print("[+] Investigation pipeline finished")
    print(f"    Status: {status}")
    print(f"    Workspace: {workspace}")
    print(f"    Manifest: {manifest_path}")

    return {
        "workspace": workspace,
        "status": status,
        "modules": modules,
        "module_results": module_results,
        "failures": failures,
        "manifest": manifest_path,
    }
