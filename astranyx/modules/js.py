import hashlib
import json
import re
from pathlib import Path
from time import perf_counter

from astranyx.investigation.manager import InvestigationManager
from astranyx.telemetry import Status, StatusCode, trace

tracer = trace.get_tracer("astranyx.modules.js")


PATTERNS = {
    "network_fetch": r"fetch\(",
    "axios": r"axios",
    "graphql": r"graphql|mutation|operationName|query",
    "oauth": r"oauth|saml|scim|sso",
    "auth": r"token|csrf|session|cookie|webauthn|passkey",
    "uploads": r"\b(?:uploads?|attachments?|files?|imports?|exports?)\b",
    "collaboration": (r"invite|team|organization|workspace|member|permission|comment"),
    "admin": r"admin|internal|staff|employee",
}


ROUTE_PATTERN = re.compile(
    r"""["'`]((?:https?://|/)[A-Za-z0-9._~:/?#@!$&()*+,;=%\-\[\]]+)["'`]"""
)

SIGNAL_PATTERNS = {
    "dynamic_code_execution": re.compile(r"(?:\beval\s*\(|\bFunction\s*\()"),
    "html_injection_sink": re.compile(
        r"\b(?:dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b",
        re.IGNORECASE,
    ),
    "cross_window_message": re.compile(r"\b(?:postMessage|MessageEvent)\b", re.IGNORECASE),
    "browser_secret_storage": re.compile(
        r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\([^)]*"
        r"(?:token|session|nonce|secret|password|codeVerifier)",
        re.IGNORECASE,
    ),
    "navigation_sink": re.compile(
        r"(?:window\.)?location\.(?:assign|replace|href)|window\.open\s*\(",
        re.IGNORECASE,
    ),
}

API_ENDPOINT_PATTERN = re.compile(
    r"\$\{[^}]+\}"
    r"(?P<path>/(?:adminOIDC|admin|appearance|dataRetention|network|public|self|session)"
    r"[A-Za-z0-9_?&=./${}:-]*)"
)

HTTP_RESOLVER_PATTERN = re.compile(
    r"(?:method\s*:\s*[\"'](?P<literal>GET|POST|PUT|DELETE|PATCH)[\"']|"
    r"getHttp(?P<resolver>Post|Put|Delete|PDF)?Resolver)",
    re.IGNORECASE,
)

MAX_SIGNALS_PER_CATEGORY_PER_FILE = 25


def _raise_analysis_error(span, error_type, message):
    """Record and raise an analysis input error."""
    span.set_attribute(
        "astranyx.error.type",
        error_type,
    )
    span.set_status(Status(StatusCode.ERROR, message))

    raise SystemExit(f"[!] {message}")


def _validate_source(base, span):
    """Validate the JavaScript source directory."""
    if not base.exists():
        _raise_analysis_error(
            span,
            "path_not_found",
            f"Path not found: {base}",
        )

    if not base.is_dir():
        _raise_analysis_error(
            span,
            "not_a_directory",
            f"Path is not a directory: {base}",
        )


def _discover_javascript_files(base, span, recursive=False):
    """Discover JavaScript files in the requested scope."""
    with tracer.start_as_current_span("astranyx.js.discover_files") as discovery_span:
        js_files = sorted(base.rglob("*.js") if recursive else base.glob("*.js"))

        discovery_span.set_attribute(
            "astranyx.javascript.files_discovered",
            len(js_files),
        )

    if not js_files:
        _raise_analysis_error(
            span,
            "no_javascript_files",
            f"No JavaScript files found in {base}",
        )

    return js_files


def _extract_findings(text):
    """Count security-related patterns in JavaScript text."""
    findings = {}

    for name, pattern in PATTERNS.items():
        matches = re.findall(
            pattern,
            text,
            flags=re.IGNORECASE,
        )

        if matches:
            findings[name] = len(matches)

    return findings


def _source_position(text, offset):
    """Return one-based line and column values for an offset."""
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return line, column


def _snippet(text, start, end, radius=140):
    """Build a compact evidence preview around a match."""
    preview = text[max(0, start - radius) : min(len(text), end + radius)]
    return re.sub(r"\s+", " ", preview).strip()


def _extract_signals(text, report_path):
    """Extract bounded, source-backed security signals."""
    signals = []
    for category, pattern in SIGNAL_PATTERNS.items():
        for match in list(pattern.finditer(text))[:MAX_SIGNALS_PER_CATEGORY_PER_FILE]:
            line, column = _source_position(text, match.start())
            signals.append(
                {
                    "category": category,
                    "file": report_path,
                    "offset": match.start(),
                    "line": line,
                    "column": column,
                    "match": match.group(0),
                    "snippet": _snippet(text, match.start(), match.end()),
                    "status": "candidate",
                }
            )
    return signals


def _infer_http_method(text, endpoint_end):
    """Infer the request method from code immediately following an endpoint."""
    nearby = text[endpoint_end : endpoint_end + 320]
    match = HTTP_RESOLVER_PATTERN.search(nearby)
    if not match:
        return "UNKNOWN"
    if match.group("literal"):
        return match.group("literal").upper()
    resolver = (match.group("resolver") or "").lower()
    return {"post": "POST", "put": "PUT", "delete": "DELETE"}.get(
        resolver, "GET"
    )


def _extract_api_endpoints(text, report_path):
    """Extract first-party API paths with method hints and source evidence."""
    endpoints = {}
    for match in API_ENDPOINT_PATTERN.finditer(text):
        path = match.group("path")
        method = _infer_http_method(text, match.end())
        if method == "UNKNOWN":
            continue
        key = (method, path)
        if key in endpoints:
            continue
        line, column = _source_position(text, match.start("path"))
        endpoints[key] = {
            "method": method,
            "path": path,
            "file": report_path,
            "offset": match.start("path"),
            "line": line,
            "column": column,
            "snippet": _snippet(text, match.start(), match.end()),
        }
    return list(endpoints.values())


def _scan_javascript_file(file_path, report_path):
    """Read and scan one JavaScript file."""
    text = file_path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    findings = _extract_findings(text)
    routes = ROUTE_PATTERN.findall(text)
    signals = _extract_signals(text, report_path)
    endpoints = _extract_api_endpoints(text, report_path)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    return text, findings, routes, signals, endpoints, digest


def _scan_javascript_files(js_files, base):
    """Scan JavaScript files and collect results."""
    results = {}
    routes = set()
    failed_files = 0
    total_findings = 0
    signals = []
    api_endpoints = []
    source_files = []

    with tracer.start_as_current_span("astranyx.js.scan_files") as scan_span:
        for file_path in js_files:
            report_path = file_path.relative_to(base).as_posix()
            with tracer.start_as_current_span("astranyx.js.scan_file") as file_span:
                file_span.set_attribute(
                    "astranyx.file.name",
                    file_path.name,
                )
                file_span.set_attribute(
                    "astranyx.file.path",
                    str(file_path),
                )

                try:
                    (
                        text,
                        findings,
                        file_routes,
                        file_signals,
                        file_endpoints,
                        digest,
                    ) = _scan_javascript_file(file_path, report_path)
                except OSError as exc:
                    failed_files += 1

                    file_span.record_exception(exc)
                    file_span.set_status(
                        Status(
                            StatusCode.ERROR,
                            str(exc),
                        )
                    )

                    print(f"[!] Failed reading {file_path}: {exc}")
                    continue

                finding_count = sum(findings.values())

                file_span.set_attribute(
                    "astranyx.file.size_characters",
                    len(text),
                )
                file_span.set_attribute(
                    "astranyx.file.finding_categories",
                    len(findings),
                )
                file_span.set_attribute(
                    "astranyx.file.findings_total",
                    finding_count,
                )
                file_span.set_attribute(
                    "astranyx.file.routes_found",
                    len(file_routes),
                )

                total_findings += finding_count
                routes.update(file_routes)
                signals.extend(file_signals)
                api_endpoints.extend(file_endpoints)
                source_files.append(
                    {
                        "path": report_path,
                        "size_bytes": file_path.stat().st_size,
                        "sha256": digest,
                    }
                )

                if findings:
                    results[report_path] = findings

        processed_files = len(js_files) - failed_files

        scan_span.set_attribute(
            "astranyx.javascript.files_processed",
            processed_files,
        )
        scan_span.set_attribute(
            "astranyx.javascript.files_failed",
            failed_files,
        )
        scan_span.set_attribute(
            "astranyx.javascript.findings_total",
            total_findings,
        )
        scan_span.set_attribute(
            "astranyx.javascript.routes_unique",
            len(routes),
        )

    return (
        results,
        routes,
        failed_files,
        total_findings,
        signals,
        api_endpoints,
        source_files,
    )


def _build_report(
    base,
    js_files,
    failed_files,
    results,
    routes,
    signals,
    api_endpoints,
    source_files,
):
    """Build the JavaScript analysis report."""
    return {
        "target": base.name,
        "files_analyzed": len(js_files) - failed_files,
        "summary": results,
        "routes": sorted(routes),
        "signals": signals,
        "api_endpoints": sorted(
            api_endpoints, key=lambda item: (item["path"], item["method"])
        ),
        "source_files": source_files,
        "report_guidance": (
            "Signals are review candidates, not validated vulnerabilities. "
            "Confirm attacker control, reachability, and security impact manually."
        ),
    }


def _write_report(output, result_json):
    """Write an optional standalone JSON report."""
    if not output:
        return None

    with tracer.start_as_current_span("astranyx.js.write_report") as output_span:
        output_path = Path(output).expanduser()

        output_span.set_attribute(
            "astranyx.output.path",
            str(output_path),
        )

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            output_path.write_text(
                result_json,
                encoding="utf-8",
            )
        except Exception as exc:
            output_span.record_exception(exc)
            output_span.set_status(
                Status(
                    StatusCode.ERROR,
                    str(exc),
                )
            )
            raise

        output_span.set_attribute(
            "astranyx.output.bytes",
            len(result_json.encode("utf-8")),
        )

    print(f"[+] Report written to {output_path}")

    return output_path


def _update_investigation(
    investigation,
    base,
    output_path,
    duration_ms,
    js_files,
    failed_files,
    results,
    total_findings,
    routes,
):
    """Update investigation metadata after analysis."""
    if not investigation:
        return

    with tracer.start_as_current_span(
        "astranyx.js.update_investigation"
    ) as metadata_span:
        try:
            manager = InvestigationManager(investigation)

            manager.set_target(str(base))

            manager.add_module(
                name="javascript",
                status="completed",
                duration_ms=duration_ms,
                details={
                    "files": len(js_files),
                    "files_processed": (len(js_files) - failed_files),
                    "files_failed": failed_files,
                    "files_with_findings": len(results),
                    "findings_total": total_findings,
                    "finding_categories": sum(
                        len(file_findings) for file_findings in results.values()
                    ),
                    "routes": len(routes),
                    "source_path": str(base),
                    "output_report": (str(output_path) if output_path else None),
                },
            )

            metadata_span.set_attribute(
                "astranyx.investigation.updated",
                True,
            )
            metadata_span.set_attribute(
                "astranyx.investigation.path",
                str(investigation),
            )
        except Exception as exc:
            metadata_span.record_exception(exc)
            metadata_span.set_status(
                Status(
                    StatusCode.ERROR,
                    str(exc),
                )
            )
            raise


def _set_final_span_attributes(
    span,
    js_files,
    failed_files,
    results,
    total_findings,
    routes,
    duration_ms,
):
    """Record final JavaScript analysis metrics."""
    span.set_attribute(
        "astranyx.javascript.files_analyzed",
        len(js_files) - failed_files,
    )
    span.set_attribute(
        "astranyx.javascript.files_with_findings",
        len(results),
    )
    span.set_attribute(
        "astranyx.javascript.findings_total",
        total_findings,
    )
    span.set_attribute(
        "astranyx.javascript.routes_unique",
        len(routes),
    )
    span.set_attribute(
        "astranyx.javascript.files_failed",
        failed_files,
    )
    span.set_attribute(
        "astranyx.duration_ms",
        duration_ms,
    )

    span.set_status(Status(StatusCode.OK))


def analyze(path, output=None, investigation=None, recursive=False):
    """
    Analyze JavaScript files for security-related patterns and routes.

    Args:
        path:
            Directory containing JavaScript files.

        output:
            Optional path where the JSON report will be written.

        investigation:
            Optional Astranyx investigation workspace. When supplied,
            metadata.json is updated automatically.

    Returns:
        Dictionary containing the JavaScript analysis report.
    """
    started = perf_counter()

    with tracer.start_as_current_span("astranyx.js.analyze") as span:
        base = Path(path).expanduser()

        span.set_attribute(
            "astranyx.module",
            "javascript",
        )
        span.set_attribute(
            "astranyx.target.path",
            str(base),
        )
        span.set_attribute(
            "astranyx.target.name",
            base.name,
        )
        span.set_attribute(
            "astranyx.output.enabled",
            output is not None,
        )
        span.set_attribute(
            "astranyx.investigation.enabled",
            investigation is not None,
        )

        if investigation:
            span.set_attribute(
                "astranyx.investigation.path",
                str(investigation),
            )

        _validate_source(base, span)

        js_files = _discover_javascript_files(
            base,
            span,
            recursive=recursive,
        )

        (
            results,
            routes,
            failed_files,
            total_findings,
            signals,
            api_endpoints,
            source_files,
        ) = _scan_javascript_files(js_files, base)

        report = _build_report(
            base,
            js_files,
            failed_files,
            results,
            routes,
            signals,
            api_endpoints,
            source_files,
        )

        result_json = json.dumps(
            report,
            indent=2,
        )

        output_path = _write_report(
            output,
            result_json,
        )

        duration_ms = round(
            (perf_counter() - started) * 1000,
            2,
        )

        _update_investigation(
            investigation,
            base,
            output_path,
            duration_ms,
            js_files,
            failed_files,
            results,
            total_findings,
            routes,
        )

        _set_final_span_attributes(
            span,
            js_files,
            failed_files,
            results,
            total_findings,
            routes,
            duration_ms,
        )

        print(result_json)

        return report
