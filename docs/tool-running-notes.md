# Tool Running Notes

The scanner container runs all selected tools against the same repository mount at `/workspace`. Generated result directories and dependency cache folders are excluded where a tool supports exclusions so scanners do not repeatedly scan their own output.

| Tool | Command shape | Raw output |
|---|---|---|
| Trivy | `trivy fs --format json` against `/workspace` | `results/raw/trivy.json` |
| Semgrep Default | `semgrep scan --config p/default --json --metrics=off` against `/workspace` | `results/raw/semgrep-default.json` |
| Semgrep Custom | `semgrep scan --config scanner/semgrep-rules.yml --json --metrics=off` against `/workspace` | `results/raw/semgrep-custom.json` |
| Gitleaks | `gitleaks detect --source /workspace --report-format json` | `results/raw/gitleaks.json` |
| Checkov | `checkov --directory /workspace --output json --soft-fail` | `results/raw/checkov.json` |
| Grype | `grype dir:/workspace -o json` | `results/raw/grype.json` |
| Snyk | `snyk test --all-projects --json-file-output` when `SNYK_TOKEN` exists | `results/raw/snyk.json` |

Semgrep is split into two dashboard entries. `semgrep-default` uses Semgrep's public default ruleset. `semgrep-custom` uses a small transparent local ruleset for CI/CD patterns that are central to this lab. The custom rules are scanner configuration, not expected coverage data. Coverage is still calculated only from actual findings mapped to scenarios.

Each wrapper writes a diagnostic record. If a scanner fails, the remaining scanners continue, and normalization still runs.
