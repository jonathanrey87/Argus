# Changelog

## Unreleased

- Added integrity-checked investigation resume with per-module checkpoints.
- Added conservative cross-module deduplication for normalized findings.
- Added a unified evidence graph linking analyzers, findings, files, and evidence.

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
