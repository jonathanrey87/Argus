# Security Policy

## System and Scope

Astranyx is a local-first security assessment and evidence platform. Covered
components include its CLI, report importers, analyzers, evidence collectors,
report generators, comparison workflows, integrity manifests, and optional
telemetry adapter.

Protected assets include customer source code, application artifacts, assessment
scope, findings, evidence, credentials, device identifiers, analyst identity,
client identity, and generated deliverables.

## Threat Model and Trust Boundaries

All scanned source code, MobSF reports, application metadata, device responses,
filenames, paths, evidence, and imported report fields are attacker-controlled.
Generated HTML, CSV, JSON, Markdown, and SARIF may be opened by testers or clients
in privileged desktop applications.

The local filesystem is the default security boundary. No assessment data is
trusted for outbound transmission merely because provider credentials exist.

## Security Invariants

- Core workflows must operate without network access.
- Telemetry must remain disabled by default and require explicit opt-in.
- Telemetry must never contain customer identities, targets, paths, filenames,
  source content, evidence, credentials, device identifiers, or exception detail.
- Untrusted inputs must be size-bounded and structurally validated.
- Imported markup must not become executable report content.
- CSV output must neutralize spreadsheet formulas.
- Generated bundles must refuse unintended overwrite and include integrity hashes.
- Sensitive device identifiers must be redacted before persistence.
- Findings must preserve source and rule provenance.
- High-severity output must be supported by evidence and must not be presented as
  confirmed exploitation without validation.
- Passed, failed, untested, and not-assessed states must remain distinguishable.

## Reportable Findings and Severity Context

Report vulnerabilities that realistically permit unauthorized disclosure of
assessment data, outbound transmission without explicit consent, integrity
bypass, path escape, arbitrary file overwrite, code execution, credential
exposure, unsafe rendering, or material falsification of security results.

Issues that silently convert untested controls into passes, discard provenance,
or label unsupported scanner output as validated findings are security-relevant.
Severity depends on reachability, sensitivity of exposed assessment data,
integrity impact, and whether exploitation crosses the local trust boundary.

## Out of Scope, Exclusions, and Accepted Risk

Vulnerabilities reported inside authorized assessment targets are Astranyx
results, not vulnerabilities in Astranyx itself. Optional third-party tools are
governed by their own security policies unless Astranyx invokes or processes
their output unsafely.

No blanket exclusion or accepted risk authorizes assessment-data collection,
unsafe parsing, integrity bypass, or unsupported security claims.

## Known Limitations and Compensating Controls

Astranyx is alpha software. Static and imported findings require analyst review
and do not prove exploitability or complete coverage. Runtime behavior,
authenticated workflows, backend services, and controls absent from supplied
evidence may remain untested.

Integrity manifests detect later modification but do not establish signer
identity. Users should protect local workspaces with operating-system access
controls and encrypt sensitive deliverables when storing or transferring them.
