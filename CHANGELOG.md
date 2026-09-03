# Changelog

## [4.0.0a5] - 2026-09-02

- Added bounded cross-file taint analysis over the language-neutral IR.
- Added conservative PHP IR extraction and WordPress integration with complete
  source-to-sink file and line evidence.
- Added explicit sanitizer barriers, deterministic ambiguity handling, and
  traversal budgets to reduce false conclusions and path explosion.
- Added versioned attack-surface graphs and bounded evidence-backed path
  correlation for JavaScript and WordPress analysis.
- Added fail-closed engagement policy enforcement, DNS rebinding defenses,
  request throttling, and a tamper-evident audit ledger.
- Added planning-only validation playbooks, approval-gated workflow state, and
  redacted, integrity-checked evidence bundles.
- Added signed third-party plugin manifests and fail-closed Linux isolation.

## [4.0.0a4] - 2026-09-01

- Fixed private-by-default telemetry startup when OpenTelemetry is installed.
- Added strict CVSS v3.1 base scoring with provenance, assessment coverage,
  severity-disagreement visibility, and JSON/CSV/SARIF/dashboard integration.

## [4.0.0a3] - 2026-08-29

- Added integrity-checked investigation resume with per-module checkpoints.
- Added conservative cross-module deduplication for normalized findings.
- Added a unified evidence graph linking analyzers, findings, files, and evidence.
- Added a sealed, self-contained HTML dashboard for every investigation checkpoint.
- Added a validated analyzer registry for extending investigation discovery and execution.
- Added verified MobSF assessment bundles, fingerprint-bound tester reviews, and
  OWASP MASVS mapping with provenance.
- Added a read-only iOS evidence and retest foundation.
- Made assessment telemetry private by default.
- Fixed package builds with modern setuptools and included investigation dashboard
  templates in wheels.

## [4.0.0a2] - 2026-08-12

- Fixed successful JavaScript module records being overwritten during investigation finalization.
- Fixed upload-pattern matching incorrectly classifying routes such as `/api/profile` as file uploads.

## [4.0.0a1] - 2026-08-10

- Renamed Argus to Astranyx.
- Renamed the Python distribution to `astranyx-engine` and the package and command-line interface to `astranyx`.
- Renamed the Orion CI and telemetry namespaces to Astranyx.
- Updated project and report metadata for the new repository identity.
- Prepared the breaking `4.0.0a1` alpha release.

## [3.1.0a1] - 2026-08-10

- Added the unified `argus investigate <target>` pipeline.
- Added automatic and explicit analysis profiles for local authorized targets.
- Added per-module failure isolation with completed, partial, and failed states.
- Added SHA-256 artifact manifests to investigation workspaces.
- Added configurable investigation workspace roots.
- Added a no-op telemetry compatibility layer for environments without tracing.
- Added WordPress report metadata for orchestration and investigation summaries.

## v1.0.0
- Added modular WordPress scanner.
- Added rule registry.
- Added analyzer and confidence scoring.
- Added basic taint analysis.
- Added HTML dashboard.
- Added JSON and CSV report output.
