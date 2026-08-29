"""End-to-end orchestration for local, authorized Astranyx investigations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace

from astranyx.investigation import dashboard, deduplication, evidence_graph, integrity
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
        "finding_report": str(output / "findings.json"),
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
    findings_path, deduplication_summary = deduplication.write(
        workspace, module_results
    )
    graph_path, graph = evidence_graph.write(workspace, deduplication_summary)
    dashboard_path = dashboard.render(
        workspace,
        manager.data,
        module_results,
        failures,
        deduplication_summary,
        graph,
    )
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
        "deduplication": {
            "artifact": findings_path.relative_to(workspace).as_posix(),
            "observations": deduplication_summary["observations"],
            "unique_findings": deduplication_summary["unique_findings"],
            "duplicates_removed": deduplication_summary["duplicates_removed"],
            "fingerprint_collisions": deduplication_summary[
                "fingerprint_collisions"
            ],
        },
        "evidence_graph": {
            "artifact": graph_path.relative_to(workspace).as_posix(),
            **graph["summary"],
        },
        "dashboard": {
            "artifact": dashboard_path.relative_to(workspace).as_posix(),
            "format": "self-contained-html",
        },
        "artifacts": artifacts,
    }

    manifest_path = workspace / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return manifest_path


def _failure(module: str, exc: Exception) -> dict:
    return {
        "module": module,
        "error_type": type(exc).__name__,
        "message": str(exc),
    }


def _run_module(
    module: str,
    target: Path,
    workspace: Path,
    manager: InvestigationManager,
    recursive: bool,
) -> dict:
    if module == "javascript":
        return _run_javascript(target, workspace, recursive)
    if module == "wordpress":
        return _run_wordpress(target, workspace, manager, recursive)
    raise ValueError(f"Unsupported investigation module: {module}")


def _finish_pipeline(
    workspace: Path,
    manager: InvestigationManager,
    modules: list[str],
    module_results: dict,
    failures: list[dict],
) -> dict:
    if not failures:
        status = "completed"
    elif module_results:
        status = "partial"
    else:
        status = "failed"

    manager.load()
    manager.finish_with_status(status)
    manifest_path = _write_manifest(
        workspace, manager, module_results, failures
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
    manager.data["recursive"] = recursive
    manager.save()
    manager.set_status("active")

    module_results = {}
    failures = []

    for module in modules:
        try:
            module_results[module] = _run_module(
                module, target_path, workspace, manager, recursive
            )
        except Exception as exc:  # noqa: BLE001 - analyzer boundary isolation
            failure = _failure(module, exc)
            failures.append(failure)
            manager.load()
            manager.add_module(
                module,
                status="failed",
                details={"error": failure},
            )
        # Seal a checkpoint after every analyzer. A process interruption can
        # therefore resume without re-running already completed work.
        manager.load()
        _write_manifest(workspace, manager, module_results, failures)

    return _finish_pipeline(
        workspace, manager, modules, module_results, failures
    )


def resume(workspace: str | Path, target: str | Path | None = None) -> dict:
    """Resume unfinished or failed modules in an existing investigation."""
    root = Path(workspace).expanduser().resolve()
    manager = InvestigationManager(root)
    metadata = manager.data

    modules = metadata.get("selected_modules")
    profile = metadata.get("profile")
    if (
        not isinstance(modules, list)
        or not modules
        or profile not in SUPPORTED_PROFILES
    ):
        raise ValueError("workspace has no valid investigation context")
    if any(module not in {"javascript", "wordpress"} for module in modules):
        raise ValueError("workspace contains unsupported selected modules")

    recorded_target = metadata.get("target")
    if not recorded_target:
        raise ValueError("workspace has no recorded target")
    target_path = Path(target or recorded_target).expanduser().resolve()
    recorded_target_path = Path(recorded_target).expanduser().resolve()
    if target is not None and target_path != recorded_target_path:
        raise ValueError("resume target does not match the workspace target")
    if not target_path.is_dir():
        raise NotADirectoryError(target_path)

    manifest_path = root / "manifest.json"
    module_results: dict = {}
    failures: list[dict] = []
    if manifest_path.exists():
        verification = integrity.verify(root)
        if not verification["valid"]:
            raise integrity.IntegrityError(
                "investigation artifacts failed integrity verification"
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sealed_context = manifest.get("investigation", {})
        context_fields = ("id", "target", "profile", "selected_modules")
        mismatches = [
            field
            for field in context_fields
            if sealed_context.get(field) != metadata.get(field)
        ]
        if mismatches:
            raise integrity.IntegrityError(
                "manifest context does not match metadata: "
                + ", ".join(mismatches)
            )
        module_results = dict(manifest.get("module_results") or {})
        failures = list(manifest.get("failures") or [])

    completed = set(module_results)
    pending = [module for module in modules if module not in completed]
    if not pending:
        raise ValueError("investigation is already complete")

    prior_status = metadata.get("status", "unknown")
    manager.record_resume(prior_status, pending)
    recursive = bool(metadata.get("recursive", True))

    failures = [item for item in failures if item.get("module") not in pending]
    for module in pending:
        try:
            module_results[module] = _run_module(
                module, target_path, root, manager, recursive
            )
        except Exception as exc:  # noqa: BLE001 - analyzer boundary isolation
            failure = _failure(module, exc)
            failures.append(failure)
            manager.load()
            manager.add_module(module, status="failed", details={"error": failure})
        manager.load()
        _write_manifest(root, manager, module_results, failures)

    return _finish_pipeline(root, manager, modules, module_results, failures)
