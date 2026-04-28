# Tool Running Notes

The scanner container runs all selected tools against the same repository mount at `/workspace`. Generated result directories and dependency cache folders are excluded where a tool supports exclusions so scanners do not repeatedly scan their own output.

| Tool | Command shape | Raw output |
|---|---|---|
| Trivy | `trivy fs --format json` against `/workspace` | `results/raw/trivy.json` |
| Semgrep | `semgrep scan --config scanner/semgrep-rules.yml --json --metrics=off` against `/workspace` | `results/raw/semgrep.json` |
| Gitleaks | `gitleaks detect --source /workspace --report-format json` | `results/raw/gitleaks.json` |
| Checkov | `checkov --directory /workspace --output json --soft-fail` | `results/raw/checkov.json` |
| Grype | `grype dir:/workspace -o json` | `results/raw/grype.json` |
| Snyk | `snyk test --all-projects --json-file-output` when `SNYK_TOKEN` exists | `results/raw/snyk.json` |

Semgrep uses a small transparent local ruleset for CI/CD patterns that are central to this lab. The rules are scanner configuration, not expected coverage data. Coverage is still calculated only from actual Semgrep findings mapped to scenarios.

Each wrapper writes a diagnostic record. If a scanner fails, the remaining scanners continue, and normalization still runs.
