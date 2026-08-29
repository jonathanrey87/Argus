<div align="center">

# ASTRANYX

**Investigation Engine**

Where signals emerge from the dark.

`Version 4.0.0a2` · `Alpha` · `Python 3.11+`

</div>

Astranyx is a security-analysis framework for reviewing source code, JavaScript bundles, and WordPress plugins.

It combines pattern discovery, data-flow analysis, validation evidence, confidence scoring, attack-surface classification, and reporting—helping analysts separate suspicious behavior from findings with demonstrated security impact.

## Core principles

Astranyx follows four operating principles:

- **Observe** — identify routes, sinks, trust boundaries, and security-relevant patterns.
- **Correlate** — connect findings with validation routines, data flow, and context.
- **Prioritize** — rank findings using evidence, confidence, and demonstrated impact.
- **Defend** — produce actionable reports and remediation guidance.

Astranyx records evidence without assuming that every suspicious response or code pattern is exploitable.

## Implemented capabilities

### JavaScript analysis

Astranyx can analyze directories containing JavaScript bundles and identify patterns associated with:

- Network requests
- Authentication and OAuth
- GraphQL
- Uploads
- Administrative functionality
- Collaboration features
- Application routes

Results can be written to JSON and associated with an Astranyx investigation workspace.

### WordPress plugin analysis

The WordPress scanner includes checks for:

- Public REST routes
- Missing authorization checks
- Dynamic includes
- Deserialization
- SSRF sinks
- SQL queries
- React dangerous sinks
- Upload functionality
- Taint-flow relationships

The analyzer applies nearby validation and safe-pattern evidence to reduce noise.

### Analysis framework

The analysis package currently includes:

- Data-flow graphs
- Call graphs
- Trust classification
- Taint analysis
- Validation-routine detection
- Evidence-based finding decisions
- Pluggable analysis stages
- A default evidence-analysis pipeline

### Evidence gate

The evidence gate rejects findings that lack observable security impact.

Current decision categories include:

| Category | Required evidence |
|---|---|
| PII disclosure | A non-empty sensitive value |
| CRLF/header injection | A separate injected response header |
| Open redirect | A final destination outside trusted domains |
| CORS | Cross-origin access to authenticated sensitive data |
| HTTP 500 | Data exposure, authorization impact, stack disclosure, or measurable availability impact |
| GraphQL | Unauthorized protected data |
| Health endpoint | Sensitive operational data rather than status alone |

A successful query, wildcard CORS header, generic server error, or public health response is not automatically considered reportable.

### Reporting

Astranyx contains support for:

- HTML
- Markdown
- JSON
- CSV
- SARIF
- Source previews
- Confidence summaries
- Risk summaries
- Attack-surface classification

Finding JSON uses a versioned schema distributed with the package. Each finding
has an `asx-` fingerprint derived from its category, relative file path, and
normalized evidence. The identity remains stable when a checkout moves or line
numbers change, enabling future baseline and retest workflows. SARIF exports
carry the same identity in `partialFingerprints`.

## Requirements

- Python 3.11 or newer
- Linux, macOS, or another Python-compatible environment
- A virtual environment is recommended

Runtime dependencies, including OpenTelemetry and Arize tracing support, are declared in `pyproject.toml` and installed automatically with Astranyx:

```bash
python -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
```

For development and testing:

```bash
python -m pip install pytest
```

## Command-line interface

Show available commands:

```bash
python -m astranyx.cli --help
```

### Analyze JavaScript

```bash
python -m astranyx.cli js analyze ./path/to/javascript
```

Write the report to a specific file:

```bash
python -m astranyx.cli js analyze ./path/to/javascript \
  --output report.json
```

Recursively discover JavaScript files in nested directories:

```bash
python -m astranyx.cli js analyze ./path/to/javascript \
  --recursive \
  --output report.json
```

Recursive reports preserve paths relative to the analysis root, such as `assets/js/app.js`.

Associate results with an investigation:

```bash
python -m astranyx.cli js analyze ./path/to/javascript \
  --investigation investigations/INV-YYYYMMDD-HHMMSS
```

### Audit a WordPress plugin

```bash
python -m astranyx.cli wordpress ./path/to/plugin
```

Only analyze plugins and code that you own or are authorized to assess.

### Run a complete assessment

Import, normalize, review, seal, and verify a mobile assessment with one command:

```bash
astranyx assess mobsf-report.json \
  --output assessments/example \
  --client "Example Corporation" \
  --consultant "Security Assessment Team"
```

Imported findings default to `needs_validation`; Astranyx never silently labels
scanner output as confirmed. Optional tester decisions are supplied in a local
JSON file keyed by stable finding fingerprint:

```json
{
  "schema_version": 1,
  "reviews": {
    "asx-example": {
      "state": "confirmed",
      "note": "Reproduced during authorized testing."
    }
  }
}
```

Allowed states are `confirmed`, `needs_validation`, `rejected`, `accepted_risk`,
and `not_tested`. Unknown fingerprints and invalid states fail closed. The
command reports success only after verifying every generated artifact against
the assessment manifest. Every assessment also includes
`reviews.template.json`, containing the exact fingerprints from that run. Copy
the template outside the sealed bundle, edit the copy's states and notes, then
pass the copy to a new assessment with `--review-file`. Editing the original
template inside the bundle intentionally invalidates its integrity manifest.

Findings include OWASP MASVS v2.1 mappings. Exact controls supplied by upstream
evidence are marked `upstream`; conservative keyword mappings identify only a
broad control group and are marked `inferred`. Unmapped findings remain explicit
rather than being assigned a fabricated compliance control.

### Import a MobSF mobile assessment

Normalize an existing MobSF static-analysis JSON report into Astranyx HTML,
JSON, CSV, and SARIF artifacts:

```bash
astranyx import mobsf mobsf-report.json --output reports/mobile-assessment
```

Add client-facing report information when preparing a deliverable:

```bash
astranyx import mobsf mobsf-report.json \
  --output reports/mobile-assessment \
  --client "Example Corporation" \
  --consultant "Security Assessment Team" \
  --assessment-title "Mobile Application Security Assessment"
```

The importer accepts Android and iOS report metadata, normalizes code and
manifest findings, removes embedded markup, constrains untrusted paths and text,
deduplicates stable finding fingerprints, and excludes MobSF checks marked as
secure. Input files are processed locally and limited to 50 MiB.

### Compare a baseline and retest

Compare two normalized Astranyx finding reports:

```bash
astranyx retest baseline/findings.json current/findings.json \
  --output reports/retest
```

The sealed retest bundle classifies findings as new, fixed, persistent, changed,
or regressed. It contains machine-readable JSON, a client-readable Markdown
summary, and a SHA-256 artifact manifest.

### Run an investigation

Create an empty workspace with default metadata:

```bash
astranyx investigate
```

Run automatic local-target detection and the compatible analyzers:

```bash
astranyx investigate ./path/to/authorized-target
```

Choose the complete local web profile and identify the analyst:

```bash
astranyx investigate /path/to/authorized-target \
  --profile web \
  --analyst "Jonathan Mendiola"
```

Available profiles are `auto`, `web`, `javascript`, and `wordpress`. Recursive
discovery is enabled by default and can be disabled with `--no-recursive`.
`--target` remains available as a compatibility alias for the positional path.

The command creates a timestamped workspace containing directories for analysis,
API evidence, HTML, JavaScript, logs, notes, reports, and screenshots. With a
target, Astranyx runs each selected analyzer, isolates module failures, updates
`metadata.json`, and writes `manifest.json` with SHA-256 hashes for every generated
analysis and report artifact.

Normalized findings from completed modules are combined in
`analysis/findings.json`. Astranyx removes only observations that share both a
stable fingerprint and matching security identity, records every contributing
module, and retains the strongest severity and confidence evidence. Conflicting
records that claim the same fingerprint are preserved and marked as collisions.
JavaScript discovery signals are not promoted to vulnerabilities solely to make
them eligible for deduplication.

Astranyx also writes `analysis/evidence-graph.json`, a deterministic graph that
links each contributing analyzer to its findings, each finding to its source
file, and supporting evidence to the findings it substantiates. Fingerprint
collisions remain separate graph nodes, and shared evidence is represented once.

Each analyzer completion also updates the sealed checkpoint. Resume a partial,
failed, or interrupted investigation without repeating successful modules:

```bash
astranyx investigate --resume investigations/INV-YYYYMMDD-HHMMSS
```

Astranyx verifies the existing artifact seal before resuming, retries only
unfinished or failed modules, and records the resume in `metadata.json`. A
different positional target may be supplied only when it resolves to the target
already recorded by the workspace.

Verify every sealed artifact before sharing or resuming an investigation:

```bash
astranyx verify investigations/INV-YYYYMMDD-HHMMSS
```

The command checks the recorded size and SHA-256 digest of every artifact and
returns a non-zero exit status for missing, modified, duplicated, or unsafe
artifact paths. Its JSON output can be retained as chain-of-custody evidence or
consumed by CI automation.

Choose a different workspace parent directory when needed:

```bash
astranyx investigate ./authorized-target \
  --workspace-root ./casework
```

### Collect read-only iOS evidence

Astranyx can use an optional `pymobiledevice3` installation to inventory a
trusted, USB-connected iPhone without changing device state. First create an
isolated environment with iOS support, create an investigation, and verify the
collector:

```bash
python -m pip install -e '.[ios]'
astranyx investigate
astranyx device doctor
```

Collect a privacy-redacted snapshot inside that investigation:

```bash
astranyx device snapshot \
  --investigation investigations/INV-YYYYMMDD-HHMMSS
```

Snapshots include device/build information, installed application metadata,
collection timestamps, and a SHA-256 manifest. Serial numbers, UDIDs, phone
numbers, Apple Account identifiers, and similar identifiers are replaced with
stable redaction tokens. Raw device output is not retained.

Compare two snapshots locally:

```bash
astranyx device compare before.json after.json -o comparison.json
```

Verify that a snapshot has not changed since collection:

```bash
astranyx device verify ios-snapshot-YYYYMMDDTHHMMSSZ.json
```

Comparison automatically verifies any sidecar manifests found beside its input
snapshots and refuses to compare evidence whose size or SHA-256 digest differs.

Device commands are intentionally read-only. They do not jailbreak devices,
bypass protections, extract credentials, or automate account actions.

Example completed workspace:

```text
investigations/INV-YYYYMMDD-HHMMSS/
├── analysis/javascript.json
├── reports/wordpress/
│   ├── index.html
│   ├── findings.csv
│   ├── findings.json
│   └── findings.sarif
├── manifest.json
└── metadata.json
```

### Generate reports

```bash
python -m astranyx.cli report ./path/to/report.json
```

## Evidence-pipeline example

```python
from astranyx.analysis.pipeline import build_default_pipeline

pipeline = build_default_pipeline()

result = pipeline.execute(
    {
        "finding_evidence": [
            {
                "category": "graphql",
                "protected_data": False,
            },
            {
                "category": "http_500",
                "data_exposure": True,
            },
        ]
    }
)

for decision in result["evidence_decisions"]:
    print(decision.reportable, decision.reason)

print("Reportable findings:", result["reportable_findings"])
```

In this example, anonymous GraphQL execution without protected data is rejected, while a server error with demonstrated data exposure is retained.

## Project structure

```text
astranyx/
├── analysis/       Evidence gates, pipeline, taint, and validation
├── commands/       CLI command implementations
├── core/           Reports, HTML, SARIF, and source previews
├── graph/          Call, data-flow, and trust graphs
├── intelligence/   Classification, scoring, risk, and recommendations
├── investigation/  Investigation workspace management
├── modules/        Language and artifact analyzers
├── output/         HTML and Markdown writers
├── parsers/        Parser interfaces
├── plugins/        Analysis and workflow plugins
├── services/       Checklists, playbooks, data, and status
└── wordpress/      WordPress scanning and analysis
```

## Testing

Run the complete test suite:

```bash
python -m pytest -q
```

The current suite covers:

- Evidence decisions
- Analysis-pipeline execution
- Validation detection
- Taint analysis
- Intermediate representation
- Call graphs
- Data-flow graphs
- Trust analysis
- Parsers
- Reports
- Review workflows
- Checklists
- Playbooks
- Status and threat functionality

## Tracing

Astranyx supports optional Arize/OpenTelemetry tracing.

Set both variables before running the CLI:

```bash
export ARIZE_SPACE_ID='your-space-id'
export ARIZE_API_KEY='your-api-key'
```

If tracing credentials are absent, Astranyx is intended to run without exporting traces.

Never commit tracing credentials, session tokens, cookies, or API keys.

## Development status

Astranyx is under active development. Current limitations include:

- Alpha APIs and data formats
- The evidence pipeline is available through `build_default_pipeline()` but is not yet connected to every scanner and report path
- Some modules use different finding models
- CLI and investigation behavior are still evolving
- Documentation and packaging require further validation

## Roadmap

Planned work includes:

- Unified finding and evidence models
- Evidence-gate integration across scanners
- Cross-file taint propagation
- Historical comparison and baselines
- Framework-specific analyzers
- Expanded report schemas
- Plugin interfaces
- Dependency and packaging cleanup
- Additional integration tests

Roadmap items are plans, not completed capabilities.

## Responsible use

## Privacy and telemetry

Astranyx is local-first. Assessment inputs, source code, evidence, findings, and
generated reports remain on the tester's machine unless the tester deliberately
moves them elsewhere. Core installation includes no telemetry dependency and
telemetry is disabled by default—even when provider credentials are present.

Optional aggregate telemetry requires installation with `.[telemetry]`, valid
provider credentials, and the explicit `ASTRANYX_TELEMETRY=true` opt-in. The
privacy filter permits command names, profiles, and numeric aggregate counts; it
drops customer paths, target names, analyst identities, filenames, evidence,
source content, and exception details.

Use Astranyx only on:

- Systems and code you own
- Local test environments
- Explicitly authorized security assessments
- Bug-bounty assets that are clearly in scope

Avoid collecting unrelated users’ private data, bypassing rate limits, causing availability impact, or treating scanner output as proof without independent validation.

## Author

Created by Jonathan Mendiola.

## License

Astranyx Community Edition is licensed under the Apache License 2.0. It can be
used, modified, and distributed—including commercially—subject to the license
terms in [LICENSE](LICENSE).

The project follows an open-core strategy: the local CLI, schemas, and core
analyzers remain the adoption layer, while future team workflows, managed
services, premium reporting, and support may be offered commercially. See
[COMMERCIALIZATION.md](COMMERCIALIZATION.md) for the product boundary.
