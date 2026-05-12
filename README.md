# CI/CD Security Lab

This repository is a safe, Docker-based CI/CD and software supply chain security lab for academic experimentation. It contains ten intentionally vulnerable scenarios mapped to OWASP CI/CD Security Risks, CWE IDs, concrete files, scanner outputs, normalized findings, and tool coverage.

The lab treats all scanners equally. Every selected tool scans the full project scope, and coverage is calculated only from real scanner findings that can be mapped to one of the ten scenario IDs. Raw finding volume is not used as a coverage score.

## Selected Tools

- Trivy
- Snyk
- Semgrep default rules
- Semgrep custom lab rules
- Semgrep combined profile
- Gitleaks
- Checkov
- Grype

Snyk runs only when `SNYK_TOKEN` is available. If no token is set, the scan continues and a warning diagnostic is written.

Semgrep is reported in three dashboard columns: `semgrep-default` for Semgrep's public default rules, `semgrep-custom` for the lab's local CI/CD policy rules, and `semgrep-combined` for both rule sets together. This keeps the comparison honest while also showing the practical result of extending Semgrep with local policy rules.

If you need to scope Snyk to a specific organization, set `SNYK_ORG` to the organization ID. For example:

```sh
SNYK_ORG=c7449d76-810c-4a87-976e-c496b7ed5c29
```

This is separate from `SNYK_TOKEN`. The org ID is not the authentication token.

## OWASP/CWE Mapping

The lab uses exactly ten stable scenario IDs:

| Scenario ID | Title | OWASP CI/CD category | CWE | Mapping | NVD CVEs |
|---|---|---|---|---|---:|
| SEC03-CWE494 | Download of Code Without Integrity Check | CICD-SEC-03: Dependency Chain Abuse | CWE-494 | ALLOWED | 105 |
| SEC03-CWE829 | Inclusion of Functionality from Untrusted Control Sphere | CICD-SEC-03: Dependency Chain Abuse | CWE-829 | ALLOWED | 141 |
| SEC04-CWE78 | Improper Neutralization of Special Elements used in an OS Command | CICD-SEC-04: Poisoned Pipeline Execution | CWE-78 | ALLOWED | 3,809 |
| SEC04-CWE266 | Incorrect Privilege Assignment | CICD-SEC-04: Poisoned Pipeline Execution | CWE-266 | ALLOWED | 144 |
| SEC06-CWE798 | Use of Hard-coded Credentials | CICD-SEC-06: Insufficient Credential Hygiene | CWE-798 | ALLOWED | 1,219 |
| SEC06-CWE532 | Insertion of Sensitive Information into Log File | CICD-SEC-06: Insufficient Credential Hygiene | CWE-532 | ALLOWED | 687 |
| SEC07-CWE250 | Execution with Unnecessary Privileges | CICD-SEC-07: Insecure System Configuration | CWE-250 | ALLOWED | 29 |
| SEC07-CWE732 | Incorrect Permission Assignment for Critical Resource | CICD-SEC-07: Insecure System Configuration | CWE-732 | ALLOWED | 1,197 |
| SEC09-CWE354 | Improper Validation of Integrity Check Value | CICD-SEC-09: Improper Artifact Integrity Validation | CWE-354 | ALLOWED | 107 |
| SEC09-CWE347 | Improper Verification of Cryptographic Signature | CICD-SEC-09: Improper Artifact Integrity Validation | CWE-347 | ALLOWED | 387 |

The mapping is a lab-specific teaching model, not an official one-to-one OWASP-to-CWE mapping. See [docs/methodology.md](docs/methodology.md) for the methodology and notes on CWE selection. The current table replaces broader earlier mappings where a more precise CWE is available, for example CWE-266 for token over-privilege, CWE-732 for IAM permission assignment, CWE-354 for mutable image integrity, and CWE-347 for provenance/signature verification.

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
- Generated CWE severity table: `results/normalized/cwe-cvss.json`
- Summary metrics: `results/summary.json`
- Scanner diagnostics: `results/diagnostics.json`

Findings that cannot be mapped to a scenario are preserved as `UNMAPPED` instead of hidden.

If no scan has run yet, the lab initializes empty but valid JSON files for findings, scenarios, summary, and diagnostics. The dashboard treats those files as a no-results state and does not require scanner output to exist before it starts.

## Coverage Calculation

Coverage is calculated from mapped vulnerable-side scenario detections only:

- Per-tool coverage = the average partial scenario credit for that tool across the 10 scenarios.
- Per-scenario coverage = the average partial scenario credit across reporting profiles.
- Combined coverage = the average partial scenario credit from the selected tools.
- CVSS-weighted coverage = the same partial scenario credit weighted by generated NVD-derived CWE CVSS context, when that data is available. The generated table stores mean, median, and 75th percentile; the selected score defaults to the median.
- Tool recommendations = the smallest reporting-profile combinations that cover selected scenarios, calculated only from mapped findings.

The partial-credit formula is:

```text
credit(t, s) = min(detections(t, s), intended(s)) / intended(s)

coverage(t) = (sum over scenarios credit(t, s)) / number_of_scenarios
```

For combined coverage over a selected tool set `T`, the same formula is used with detections from all selected tools:

```text
credit(T, s) = min(detections(T, s), intended(s)) / intended(s)

coverage(T) = (sum over scenarios credit(T, s)) / number_of_scenarios
```

For example, if a scenario has 7 intended vulnerable instances and a tool produces 2 coverage-eligible findings for that scenario, the scenario contributes `2/7 = 28.6%` credit for that tool, not full scenario credit.

CVSS-weighted coverage uses the same credit value:

```text
cvss_weighted_coverage(T) =
  sum over scenarios (cvss_weight(s) * credit(T, s))
  / sum over scenarios cvss_weight(s)
```

Raw finding count is not a coverage metric. A tool with many unmapped findings is not automatically better than a tool with fewer findings mapped to relevant lab scenarios.

The dashboard also separates raw finding volume from scenario credit. A tool may produce several findings for one scenario because it reports multiple package CVEs, multiple IaC rule hits, or repeated evidence in the same vulnerable example. Those findings remain visible in the raw findings view, but the matrix caps credited detections at the scenario's intended vulnerability count and labels the remaining entries as extra raw findings. Findings in fixed examples or outside scenario evidence can still be mapped for auditability, but they are marked as non-coverage evidence and do not count as scenario detection. This prevents duplicate, fixed-side, or unrelated project findings from making coverage look stronger than it is. The MVP does not manually label each individual intended vulnerability instance, so partial credit is based on coverage-eligible finding counts capped by `intendedVulnerabilityCount`.

The selected scanner families are the six original tools. The dashboard separates Semgrep into `semgrep-default`, `semgrep-custom`, and `semgrep-combined`, so the UI may show eight reporting profiles. This split is intentional and prevents custom policy rules from being mistaken for out-of-the-box Semgrep behavior.

CVSS is formally defined for concrete vulnerabilities, not CWE classes. The lab therefore uses a generated CWE severity table only as analysis context, based on NVD CVEs mapped to each CWE. Each CVE contributes one preferred CVSS v3 score, using CVSS v3.1 first and then v3.0. The table stores mean, median, and 75th percentile values; `CWE_CVSS_SELECTED_STATISTIC` chooses which value is used as `baseScore`, and defaults to `median`. It does not replace the original scenario coverage metric. The table is refreshed when the CWE set changes, when the selected statistic changes, when it is missing, or when it is older than 30 days. Timeout, disabled lookup, or generator failure entries are not treated as fresh cache entries. The generator follows NVD-friendly defaults: 2000 results per page, 60 second timeout, `noRejected`, and a 6 second delay without an API key. It also supports `NVD_API_KEY` when available. If NVD data cannot be fetched or a CWE has no usable CVSS data, the table records `UNKNOWN` instead of inventing a local score.

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
