import argparse
import json
from pathlib import Path

from astranyx import __version__
from astranyx.assessment import workflow as assessment_workflow
from astranyx.commands import report as report_command
from astranyx.comparison import retest
from astranyx.device import ios
from astranyx.engagement.policy import EngagementPolicy, PolicyError
from astranyx.evidence import (
    EvidenceError,
    capture_bundle,
    compare_bundles,
    verify_bundle,
)
from astranyx.graph.reporting import build_report, load_graph, render_report
from astranyx.importers import mobsf
from astranyx.investigation import integrity, orchestrator
from astranyx.investigation import run as investigation_command
from astranyx.modules import js
from astranyx.plugin_runtime import (
    IsolatedPluginRunner,
    PluginError,
    PluginManifest,
    sign_manifest,
    verify_signature,
)
from astranyx.tracing import configure_tracing
from astranyx.validation.playbook import (
    generate_plans,
    load_attack_path_report,
    render_plans,
)
from astranyx.wordpress import scanner
from astranyx.workflow import ValidationWorkflow, WorkflowError


def run_js(args):
    """Run JavaScript analysis."""
    js.analyze(
        path=args.path,
        output=args.output,
        investigation=args.investigation,
        recursive=args.recursive,
    )


def run_report(args):
    """Generate reports from an Astranyx JSON report."""
    report_command.run(args.report_json)


def run_wordpress(args):
    """Run the WordPress plugin scanner."""
    scanner.run(args.path)


def run_investigation(args):
    """Create a workspace and optionally run an investigation pipeline."""
    positional_target = getattr(args, "path", None)
    option_target = getattr(args, "target", None)

    if (
        positional_target
        and option_target
        and str(positional_target) != str(option_target)
    ):
        raise SystemExit(
            "[!] Supply the target either positionally or with --target, not both"
        )

    target = positional_target or option_target
    args.target = target

    resume_workspace = getattr(args, "resume", None)
    if resume_workspace:
        try:
            return orchestrator.resume(resume_workspace, target=target)
        except (
            FileNotFoundError,
            NotADirectoryError,
            ValueError,
            integrity.IntegrityError,
        ) as exc:
            raise SystemExit(f"[!] {exc}") from exc

    if target is None:
        return investigation_command.run(args)

    try:
        return orchestrator.run(
            target,
            analyst=args.analyst,
            profile=args.profile,
            recursive=args.recursive,
            trace_enabled=args.trace_enabled,
            workspace_root=args.workspace_root,
        )
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        raise SystemExit(f"[!] {exc}") from exc


def run_device_doctor(args):
    """Report whether read-only iOS collection is available."""
    result = ios.doctor()
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["ready"]:
        raise SystemExit(1)


def run_device_snapshot(args):
    """Collect redacted, read-only iOS evidence."""
    try:
        path = ios.snapshot(args.investigation)
    except ios.DeviceCollectionError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(path)


def run_device_compare(args):
    """Compare two previously collected iOS snapshots."""
    try:
        result = ios.compare_snapshots(args.before, args.after)
    except ios.DeviceCollectionError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(args.output)
    else:
        print(rendered, end="")


def run_device_verify(args):
    """Verify an iOS snapshot against its integrity manifest."""
    try:
        result = ios.verify_snapshot(args.snapshot)
    except ios.DeviceCollectionError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_verify(args):
    """Verify every artifact sealed in an investigation manifest."""
    try:
        result = integrity.verify(args.workspace)
    except integrity.IntegrityError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(1)


def run_import_mobsf(args):
    """Import a MobSF report into normalized Astranyx artifacts."""
    try:
        result = mobsf.import_report(
            args.report,
            args.output,
            client=args.client,
            consultant=args.consultant,
            assessment_title=args.assessment_title,
        )
    except mobsf.MobSFImportError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_retest(args):
    """Compare a baseline assessment with a current retest."""
    try:
        result = retest.write_report(args.baseline, args.current, args.output)
    except retest.RetestError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_assess(args):
    """Run the complete local-first mobile assessment workflow."""
    try:
        result = assessment_workflow.run(
            args.report,
            args.output,
            client=args.client,
            consultant=args.consultant,
            assessment_title=args.assessment_title,
            review_file=args.review_file,
        )
    except assessment_workflow.AssessmentError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_engagement_validate(args):
    """Validate and summarize a rules-of-engagement policy."""
    try:
        policy = EngagementPolicy.load(args.policy)
    except PolicyError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(policy.summary(), indent=2, sort_keys=True))


def run_engagement_authorize(args):
    """Evaluate one proposed request against a rules-of-engagement policy."""
    try:
        policy = EngagementPolicy.load(args.policy)
        decision = policy.authorize(args.url, args.method)
    except PolicyError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    if not decision.allowed:
        raise SystemExit(2)


def run_graph_correlate(args):
    """Correlate explicit paths in a versioned attack-surface graph."""
    try:
        graph = load_graph(args.graph_json)
        report = build_report(
            graph,
            max_depth=args.max_depth,
            max_paths=args.max_paths,
            max_states=args.max_states,
        )
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"[!] {exc}") from exc
    rendered = render_report(report)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(args.output)
    else:
        print(rendered, end="")


def run_validation_plan(args):
    """Generate planning-only validation playbooks from correlated paths."""
    try:
        rendered = render_plans(generate_plans(load_attack_path_report(args.report)))
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"[!] {exc}") from exc
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(args.output)
    else:
        print(rendered, end="")


def run_evidence_capture(args):
    """Capture local UTF-8 evidence into a redacted sealed bundle."""
    try:
        result = capture_bundle(
            args.plan, args.sources, args.output, plan_id=args.plan_id
        )
    except EvidenceError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_evidence_verify(args):
    """Verify a sealed evidence bundle."""
    try:
        result = verify_bundle(args.bundle)
    except EvidenceError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(1)


def run_evidence_compare(args):
    """Compare two verified bundles for the same validation plan."""
    try:
        result = compare_bundles(args.baseline, args.current)
    except EvidenceError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_workflow_create(args):
    try:
        workflow = ValidationWorkflow.create(
            args.plan, args.workspace, creator=args.actor, plan_id=args.plan_id
        )
        result = workflow.status()
    except WorkflowError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_workflow_approve(args):
    try:
        result = ValidationWorkflow(args.workspace).approve(
            approver=args.actor, valid_hours=args.valid_hours
        )
    except WorkflowError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_workflow_begin(args):
    try:
        result = ValidationWorkflow(args.workspace).begin(executor=args.actor)
    except WorkflowError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_workflow_verify(args):
    try:
        result = ValidationWorkflow(args.workspace).verify(
            args.evidence, verifier=args.actor
        )
    except WorkflowError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_workflow_report(args):
    try:
        result = ValidationWorkflow(args.workspace).report(
            args.output, reporter=args.actor
        )
    except WorkflowError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_workflow_status(args):
    try:
        result = ValidationWorkflow(args.workspace).status()
    except WorkflowError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_plugin_doctor(args):
    result = IsolatedPluginRunner().doctor()
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["ready"]:
        raise SystemExit(1)


def run_plugin_validate(args):
    try:
        manifest, _ = PluginManifest.load(args.plugin)
        if args.keyring:
            verify_signature(manifest, args.keyring)
    except PluginError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    result = manifest.summary()
    result["signature_verified"] = bool(args.keyring)
    print(json.dumps(result, indent=2, sort_keys=True))


def run_plugin_sign(args):
    try:
        manifest = sign_manifest(args.plugin, args.private_key, args.key_id)
    except PluginError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(
        json.dumps(
            {
                "name": manifest.name,
                "version": manifest.version,
                "publisher_key_id": manifest.publisher_key_id,
                "signature_algorithm": manifest.signature_algorithm,
                "signed": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


def run_plugin_isolated(args):
    try:
        parameters = json.loads(args.parameters) if args.parameters else {}
        if not isinstance(parameters, dict):
            raise PluginError("plugin parameters must be a JSON object")
        result = IsolatedPluginRunner(keyring=args.keyring).run(
            args.plugin,
            inputs=args.input,
            output=args.output,
            parameters=parameters,
        )
    except (json.JSONDecodeError, PluginError) as exc:
        raise SystemExit(f"[!] {exc}") from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def main():
    """Astranyx command-line entry point."""
    tracer = configure_tracing()

    parser = argparse.ArgumentParser(
        prog="astranyx",
        description=("Astranyx Threat Intelligence Automation Framework"),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # Read-only iOS evidence commands
    device_parser = subparsers.add_parser(
        "device",
        help="Collect and compare read-only device evidence",
    )
    device_subparsers = device_parser.add_subparsers(dest="device_command")

    device_doctor = device_subparsers.add_parser(
        "doctor",
        help="Check iOS collector and trusted USB device availability",
    )
    device_doctor.set_defaults(func=run_device_doctor)

    device_snapshot = device_subparsers.add_parser(
        "snapshot",
        help="Collect a redacted iOS snapshot",
    )
    device_snapshot.add_argument(
        "--investigation",
        required=True,
        help="Existing Astranyx investigation workspace",
    )
    device_snapshot.set_defaults(func=run_device_snapshot)

    device_compare = device_subparsers.add_parser(
        "compare",
        help="Compare two iOS snapshots without contacting a device",
    )
    device_compare.add_argument("before", help="Earlier snapshot JSON")
    device_compare.add_argument("after", help="Later snapshot JSON")
    device_compare.add_argument("-o", "--output", help="Optional output JSON")
    device_compare.set_defaults(func=run_device_compare)

    device_verify = device_subparsers.add_parser(
        "verify",
        help="Verify a snapshot against its SHA-256 manifest",
    )
    device_verify.add_argument("snapshot", help="Snapshot JSON to verify")
    device_verify.set_defaults(func=run_device_verify)

    # JavaScript commands
    js_parser = subparsers.add_parser(
        "js",
        help="JavaScript analysis",
    )

    js_subparsers = js_parser.add_subparsers(
        dest="js_command",
    )

    analyze_parser = js_subparsers.add_parser(
        "analyze",
        help="Analyze JavaScript bundles",
    )

    analyze_parser.add_argument(
        "path",
        help="Directory containing JavaScript files",
    )

    analyze_parser.add_argument(
        "-o",
        "--output",
        help="Optional path for the JSON report",
    )

    analyze_parser.add_argument(
        "--investigation",
        help=(
            "Path to an Astranyx investigation workspace, "
            "for example investigations/INV-20260721-171856"
        ),
    )

    analyze_parser.add_argument(
        "--recursive",
        action="store_true",
        help="Discover JavaScript files in nested directories",
    )

    analyze_parser.set_defaults(func=run_js)

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate HTML and Markdown reports",
    )

    report_parser.add_argument(
        "report_json",
        help="Path to an Astranyx JSON report",
    )

    report_parser.set_defaults(func=run_report)

    # WordPress command
    wordpress_parser = subparsers.add_parser(
        "wordpress",
        help="Audit a WordPress plugin",
    )

    wordpress_parser.add_argument(
        "path",
        help="Path to the WordPress plugin directory",
    )

    wordpress_parser.set_defaults(func=run_wordpress)

    import_parser = subparsers.add_parser(
        "import",
        help="Import findings from an external security tool",
    )
    import_subparsers = import_parser.add_subparsers(dest="import_format")
    import_mobsf = import_subparsers.add_parser(
        "mobsf",
        help="Import a MobSF static-analysis JSON report",
    )
    import_mobsf.add_argument("report", help="MobSF JSON report")
    import_mobsf.add_argument(
        "-o",
        "--output",
        required=True,
        help="Directory for normalized Astranyx report artifacts",
    )
    import_mobsf.add_argument("--client", default="", help="Client name for the report")
    import_mobsf.add_argument(
        "--consultant", default="", help="Consultant or assessment team"
    )
    import_mobsf.add_argument(
        "--assessment-title",
        default="",
        help="Custom title for the client deliverable",
    )
    import_mobsf.set_defaults(func=run_import_mobsf)

    assess_parser = subparsers.add_parser(
        "assess",
        help="Import, review, seal, and verify a mobile assessment",
    )
    assess_parser.add_argument("report", help="MobSF static-analysis JSON report")
    assess_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="New directory for the verified assessment bundle",
    )
    assess_parser.add_argument("--client", default="", help="Client name")
    assess_parser.add_argument(
        "--consultant", default="", help="Consultant or assessment team"
    )
    assess_parser.add_argument(
        "--assessment-title", default="", help="Client-facing assessment title"
    )
    assess_parser.add_argument(
        "--review-file",
        help="Optional JSON decisions keyed by Astranyx fingerprint",
    )
    assess_parser.set_defaults(func=run_assess)

    retest_parser = subparsers.add_parser(
        "retest",
        help="Compare baseline and current Astranyx finding reports",
    )
    retest_parser.add_argument("baseline", help="Earlier findings.json report")
    retest_parser.add_argument("current", help="Current findings.json report")
    retest_parser.add_argument(
        "-o", "--output", required=True, help="Directory for the sealed retest bundle"
    )
    retest_parser.set_defaults(func=run_retest)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify the integrity of an investigation workspace",
    )
    verify_parser.add_argument(
        "workspace",
        help="Investigation workspace containing manifest.json",
    )
    verify_parser.set_defaults(func=run_verify)

    engagement_parser = subparsers.add_parser(
        "engagement",
        help="Validate scope and authorize proposed assessment requests",
    )
    engagement_subparsers = engagement_parser.add_subparsers(dest="engagement_command")
    engagement_validate = engagement_subparsers.add_parser(
        "validate",
        help="Validate and summarize a rules-of-engagement policy",
    )
    engagement_validate.add_argument("policy", help="Engagement policy JSON")
    engagement_validate.set_defaults(func=run_engagement_validate)

    engagement_authorize = engagement_subparsers.add_parser(
        "authorize",
        help="Authorize one proposed HTTP request without sending it",
    )
    engagement_authorize.add_argument("policy", help="Engagement policy JSON")
    engagement_authorize.add_argument("url", help="Proposed target URL")
    engagement_authorize.add_argument(
        "--method", default="GET", help="Proposed HTTP method (default: GET)"
    )
    engagement_authorize.set_defaults(func=run_engagement_authorize)

    graph_parser = subparsers.add_parser(
        "graph",
        help="Build and correlate evidence-backed attack-surface graphs",
    )
    graph_subparsers = graph_parser.add_subparsers(dest="graph_command")
    graph_correlate = graph_subparsers.add_parser(
        "correlate",
        help="Correlate explicit source-to-sink paths in graph JSON",
    )
    graph_correlate.add_argument(
        "graph_json", help="Versioned graph or graph report JSON"
    )
    graph_correlate.add_argument("-o", "--output", help="Optional report JSON output")
    graph_correlate.add_argument("--max-depth", type=int, default=16)
    graph_correlate.add_argument("--max-paths", type=int, default=1_000)
    graph_correlate.add_argument("--max-states", type=int, default=100_000)
    graph_correlate.set_defaults(func=run_graph_correlate)

    validation_parser = subparsers.add_parser(
        "validation", help="Generate approval-gated validation plans"
    )
    validation_subparsers = validation_parser.add_subparsers(dest="validation_command")
    validation_plan = validation_subparsers.add_parser(
        "plan", help="Generate non-executing plans from an attack-path report"
    )
    validation_plan.add_argument("report", help="Attack-path report JSON")
    validation_plan.add_argument("-o", "--output", help="Optional validation-plan JSON")
    validation_plan.set_defaults(func=run_validation_plan)

    evidence_parser = subparsers.add_parser(
        "evidence", help="Capture, verify, and compare sealed local evidence"
    )
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command")
    evidence_capture = evidence_subparsers.add_parser(
        "capture", help="Redact and seal local UTF-8 evidence files"
    )
    evidence_capture.add_argument("plan", help="Validation-plan JSON")
    evidence_capture.add_argument("sources", nargs="+", help="Local evidence files")
    evidence_capture.add_argument(
        "-o", "--output", required=True, help="New bundle directory"
    )
    evidence_capture.add_argument(
        "--plan-id", help="Plan ID when the document contains multiple plans"
    )
    evidence_capture.set_defaults(func=run_evidence_capture)
    evidence_verify = evidence_subparsers.add_parser(
        "verify", help="Verify evidence bundle integrity"
    )
    evidence_verify.add_argument("bundle")
    evidence_verify.set_defaults(func=run_evidence_verify)
    evidence_compare = evidence_subparsers.add_parser(
        "compare", help="Compare evidence captured for the same validation plan"
    )
    evidence_compare.add_argument("baseline")
    evidence_compare.add_argument("current")
    evidence_compare.set_defaults(func=run_evidence_compare)

    workflow_parser = subparsers.add_parser(
        "workflow", help="Manage approval-gated validation state"
    )
    workflow_subparsers = workflow_parser.add_subparsers(dest="workflow_command")
    workflow_create = workflow_subparsers.add_parser("create")
    workflow_create.add_argument("plan")
    workflow_create.add_argument("workspace")
    workflow_create.add_argument("--actor", required=True)
    workflow_create.add_argument("--plan-id")
    workflow_create.set_defaults(func=run_workflow_create)
    workflow_approve = workflow_subparsers.add_parser("approve")
    workflow_approve.add_argument("workspace")
    workflow_approve.add_argument("--actor", required=True)
    workflow_approve.add_argument("--valid-hours", type=int, default=8)
    workflow_approve.set_defaults(func=run_workflow_approve)
    workflow_begin = workflow_subparsers.add_parser("begin")
    workflow_begin.add_argument("workspace")
    workflow_begin.add_argument("--actor", required=True)
    workflow_begin.set_defaults(func=run_workflow_begin)
    workflow_verify = workflow_subparsers.add_parser("verify")
    workflow_verify.add_argument("workspace")
    workflow_verify.add_argument("evidence")
    workflow_verify.add_argument("--actor", required=True)
    workflow_verify.set_defaults(func=run_workflow_verify)
    workflow_report = workflow_subparsers.add_parser("report")
    workflow_report.add_argument("workspace")
    workflow_report.add_argument("-o", "--output", required=True)
    workflow_report.add_argument("--actor", required=True)
    workflow_report.set_defaults(func=run_workflow_report)
    workflow_status = workflow_subparsers.add_parser("status")
    workflow_status.add_argument("workspace")
    workflow_status.set_defaults(func=run_workflow_status)

    plugin_parser = subparsers.add_parser(
        "plugin", help="Validate and run isolated third-party plugins"
    )
    plugin_subparsers = plugin_parser.add_subparsers(dest="plugin_command")
    plugin_doctor = plugin_subparsers.add_parser(
        "doctor", help="Check whether the OS isolation backend is enforceable"
    )
    plugin_doctor.set_defaults(func=run_plugin_doctor)
    plugin_validate = plugin_subparsers.add_parser(
        "validate", help="Validate a plugin manifest and entrypoint digest"
    )
    plugin_validate.add_argument("plugin")
    plugin_validate.add_argument(
        "--keyring", help="Verify against this trusted keyring"
    )
    plugin_validate.set_defaults(func=run_plugin_validate)
    plugin_sign = plugin_subparsers.add_parser(
        "sign", help="Sign a plugin manifest with an Ed25519 private key"
    )
    plugin_sign.add_argument("plugin")
    plugin_sign.add_argument("--private-key", required=True)
    plugin_sign.add_argument("--key-id", required=True)
    plugin_sign.set_defaults(func=run_plugin_sign)
    plugin_run = plugin_subparsers.add_parser(
        "run", help="Run a plugin in a fail-closed OS sandbox"
    )
    plugin_run.add_argument("plugin")
    plugin_run.add_argument("--keyring", required=True)
    plugin_run.add_argument("--input", action="append", default=[])
    plugin_run.add_argument("--output")
    plugin_run.add_argument("--parameters", help="JSON object passed on stdin")
    plugin_run.set_defaults(func=run_plugin_isolated)

    # Investigation command
    investigation_parser = subparsers.add_parser(
        "investigate",
        help="Create or run an investigation",
        description=(
            "Create an investigation workspace and, when a local target is "
            "supplied, run the selected analysis profile"
        ),
    )

    investigation_parser.add_argument(
        "path",
        nargs="?",
        help="Optional local, authorized target to analyze",
    )

    investigation_parser.add_argument(
        "--analyst",
        default="unspecified",
        help="Name of the analyst creating the investigation",
    )

    investigation_parser.add_argument(
        "--target",
        help="Compatibility alias for the positional target path",
    )

    investigation_parser.add_argument(
        "--profile",
        choices=orchestrator.SUPPORTED_PROFILES,
        default="auto",
        help="Analysis profile (default: auto)",
    )

    investigation_parser.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Discover supported source files recursively (default: enabled)",
    )

    investigation_parser.add_argument(
        "--workspace-root",
        default="investigations",
        help="Parent directory for investigation workspaces",
    )

    investigation_parser.add_argument(
        "--resume",
        metavar="WORKSPACE",
        help="Resume unfinished or failed modules in an existing workspace",
    )

    investigation_parser.set_defaults(
        func=run_investigation,
    )

    args = parser.parse_args()
    args.trace_enabled = tracer is not None

    if not hasattr(args, "func"):
        parser.print_help()
        return

    # Run normally when tracing credentials are unavailable.
    if tracer is None:
        args.func(args)
        return

    span_name = f"astranyx.cli.{args.command}"

    with tracer.start_as_current_span(span_name) as span:
        span.set_attribute(
            "astranyx.command",
            args.command,
        )

        if getattr(args, "js_command", None):
            span.set_attribute(
                "astranyx.subcommand",
                args.js_command,
            )

        if getattr(args, "path", None):
            span.set_attribute(
                "astranyx.input.path",
                str(args.path),
            )

        if getattr(args, "investigation", None):
            span.set_attribute(
                "astranyx.investigation.path",
                str(args.investigation),
            )

        if getattr(args, "recursive", False):
            span.set_attribute(
                "astranyx.javascript.recursive",
                True,
            )

        if getattr(args, "target", None):
            span.set_attribute(
                "astranyx.target",
                str(args.target),
            )

        if getattr(args, "analyst", None):
            span.set_attribute(
                "astranyx.analyst",
                str(args.analyst),
            )

        if getattr(args, "profile", None):
            span.set_attribute(
                "astranyx.investigation.profile",
                str(args.profile),
            )

        args.func(args)


if __name__ == "__main__":
    main()
