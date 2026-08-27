import argparse
import json
from pathlib import Path

from astranyx import __version__
from astranyx.commands import report as report_command
from astranyx.comparison import retest
from astranyx.device import ios
from astranyx.importers import mobsf
from astranyx.investigation import integrity, orchestrator
from astranyx.investigation import run as investigation_command
from astranyx.modules import js
from astranyx.tracing import configure_tracing
from astranyx.wordpress import scanner


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
        result = mobsf.import_report(args.report, args.output)
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
    import_mobsf.set_defaults(func=run_import_mobsf)

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
