# CI/CD Security Lab

This repository is a safe, Docker-based CI/CD and software supply chain security lab for academic experimentation. It contains ten intentionally vulnerable scenarios mapped to OWASP CI/CD Security Risks, CWE IDs, concrete files, scanner outputs, normalized findings, and tool coverage.

The lab treats all scanners equally. Every selected tool scans the full project scope, and coverage is calculated only from real scanner findings that can be mapped to one of the ten scenario IDs. Raw finding volume is not used as a coverage score.

## Selected Tools

- Trivy
- Snyk
- Semgrep default rules
- Semgrep custom lab rules
- Gitleaks
- Checkov
- Grype

Snyk runs only when `SNYK_TOKEN` is available. If no token is set, the scan continues and a warning diagnostic is written.

Semgrep is reported in two separate dashboard columns: `semgrep-default` for Semgrep's public default rules and `semgrep-custom` for the lab's local CI/CD policy rules. This keeps the comparison honest: custom rules show what policy-as-code can detect, while default rules show less tailored coverage.

If you need to scope Snyk to a specific organization, set `SNYK_ORG` to the organization ID. For example:

```sh
SNYK_ORG=c7449d76-810c-4a87-976e-c496b7ed5c29
```

This is separate from `SNYK_TOKEN`. The org ID is not the authentication token.

## OWASP/CWE Mapping

The lab uses exactly ten stable scenario IDs:

| Scenario ID | Title | OWASP CI/CD category | CWE |
|---|---|---|---|
| SEC03-CWE494 | Integrity Omission | CICD-SEC-03: Dependency Chain Abuse | CWE-494 |
| SEC03-CWE829 | Untrusted Dependency Resolution | CICD-SEC-03: Dependency Chain Abuse | CWE-829 |
| SEC04-CWE78 | Tainted Command Injection | CICD-SEC-04: Poisoned Pipeline Execution | CWE-78 |
| SEC04-CWE269 | Token Over-privilege | CICD-SEC-04: Poisoned Pipeline Execution | CWE-269 |
| SEC06-CWE798 | Hardcoded Secret | CICD-SEC-06: Insufficient Credential Hygiene | CWE-798 |
| SEC06-CWE532 | Verbose Log Leak | CICD-SEC-06: Insufficient Credential Hygiene | CWE-532 |
| SEC07-CWE16 | Insecure Container Default | CICD-SEC-07: Insecure System Configuration | CWE-16 |
| SEC07-CWE269 | Overprivileged Cloud Identity | CICD-SEC-07: Insecure System Configuration | CWE-269 |
| SEC09-CWE345-A | Mutable Image Tags | CICD-SEC-09: Improper Artifact Integrity Validation | CWE-345 |
| SEC09-CWE345-B | Unverified Provenance | CICD-SEC-09: Improper Artifact Integrity Validation | CWE-345 |

The mapping is a lab-specific teaching model, not an official one-to-one OWASP-to-CWE mapping. See [docs/methodology.md](docs/methodology.md) for the methodology and notes on broad CWEs such as CWE-16 and CWE-345.

## Run The Lab

Build scanners, run all scans, normalize results, and start the dashboard:

```sh
docker compose up --build
```

The dashboard is served at:

```text
http://localhost:5173
```

## Make Commands

```sh
make scan
make dashboard
make all
make clean
```

- `make scan` runs all scanner wrappers and writes results.
- `make dashboard` starts only the dashboard service.
- `make all` runs the complete Docker Compose stack.
- `make clean` removes generated scanner output and writes empty valid result JSON files.

## Result Storage

- Raw scanner output: `results/raw/`
- Normalized findings: `results/normalized/findings.json`
- Generated scenario catalog: `results/normalized/scenarios.json`
- Summary metrics: `results/summary.json`
- Scanner diagnostics: `results/diagnostics.json`

Findings that cannot be mapped to a scenario are preserved as `UNMAPPED` instead of hidden.

If no scan has run yet, the lab initializes empty but valid JSON files for findings, scenarios, summary, and diagnostics. The dashboard treats those files as a no-results state and does not require scanner output to exist before it starts.

## Coverage Calculation

Coverage is calculated from mapped scenario detections only:

- Per-tool coverage = unique mapped scenarios detected by that tool / 10.
- Per-scenario coverage = reporting profiles detecting that scenario / number of reporting profiles.
- Combined coverage = union of mapped scenarios detected by selected tools / 10.

Raw finding count is not a coverage metric. A tool with many unmapped findings is not automatically better than a tool with fewer findings mapped to relevant lab scenarios.

The selected scanner families are the six original tools. The dashboard separates Semgrep into `semgrep-default` and `semgrep-custom`, so the UI may show seven reporting profiles. This split is intentional and prevents custom policy rules from being mistaken for out-of-the-box Semgrep behavior.

## Expected Coverage

[docs/expected-tool-coverage.md](docs/expected-tool-coverage.md) contains a theoretical table with `TBD` values only. It is for later academic discussion and is not used to run scanners, parse outputs, map findings, suppress findings, or calculate scores.

## Safety Limitations

All scenarios are local and harmless. Fake secrets are clearly marked as fake test data. The lab does not create malware, persistence, destructive behavior, real cloud resources, or real exfiltration. Examples that demonstrate unsafe patterns use comments, local mock files, or harmless shell commands.

## Add A Scenario

1. Add a new folder under `scenarios/`.
2. Include `vulnerable/`, `fixed/`, `README.md`, and `metadata.json`.
3. Give the scenario a stable `id`.
4. Add vulnerable and fixed file paths to `metadata.json`.
5. Add mapping hints only for path or content mapping. Do not add expected tool coverage.
6. Update `docs/scenario-matrix.md`.

The dashboard and normalization code load scenario metadata dynamically, but this MVP's coverage denominator is intentionally fixed at ten scenarios.

## Add A Tool Parser

1. Add a wrapper under `scanner/tools/`.
2. Write raw JSON output to `results/raw/`.
3. Add a parser under `scanner/parsers/`.
4. Register the parser in `scanner/normalize-results.js`.
5. Emit diagnostics even when the tool fails or is skipped.

Parsers should preserve unmapped findings and normalize severities into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `UNKNOWN`.
