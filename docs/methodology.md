# Methodology

This lab maps OWASP CI/CD Security Risk categories to concrete CWE-backed scenarios for repeatable academic testing.

The CWE mapping is not an official one-to-one OWASP mapping. OWASP CI/CD categories describe pipeline-level risk areas, while CWEs describe underlying software, configuration, or design weaknesses. The lab narrows broad CI/CD risks into concrete examples that can be stored in files, scanned by tools, normalized, and discussed.

All tools are treated equally. The scanner container runs every available tool against the full lab. Expected coverage is not used to decide scanner execution, parsing, finding mapping, suppression, or scoring.

Semgrep is represented as three reporting profiles: `semgrep-default`, `semgrep-custom`, and `semgrep-combined`. The default entry uses Semgrep's public default ruleset. The custom entry uses local CI/CD policy rules written in the style a team might maintain for its own repositories. The combined entry runs both rule sets together. These rules are intentionally generic and are not designed to match every lab scenario, every scenario ID, or every fake secret. This separation avoids presenting policy-as-code results as out-of-the-box scanner behavior while still showing the practical effect of combining default and local policy rules.

Actual scanner output is the only source of coverage. A scenario receives coverage credit from a tool only when that tool emits findings that map to the vulnerable-side evidence for that scenario. If a scenario contains several intended vulnerable instances, coverage is fractional: two detections in a scenario with seven intended instances count as `2/7`, not full scenario coverage. If a finding cannot be mapped, it remains visible as `UNMAPPED`.

Raw finding volume is preserved but is not allowed to inflate coverage. Some scanners can emit several findings for the same lab scenario, for example one dependency scenario can produce multiple package CVEs or one container scenario can trigger several configuration rules. The normalized output therefore keeps every raw finding, marks exact duplicate groups where possible, and also marks extra raw findings when a tool reports more coverage-eligible findings for a scenario than the scenario's intended vulnerability count. Findings in `fixed/` examples or outside the scenario evidence can still be mapped for auditability, but they are marked as non-coverage evidence. The dashboard credits only the capped vulnerable-side scenario detection count in the matrix, while still showing the extra and non-coverage findings for review.

The tool recommendation view uses the same rule in reverse. The user selects scenarios, and the dashboard calculates the smallest reporting-profile combinations that cover those selected scenarios. It does not use expected coverage, raw finding counts, or manual assumptions.

Results depend on tool version, rule configuration, scan target, network availability for vulnerability databases, and parser quality. The dashboard separates raw findings, mapped findings, coverage, and diagnostics so those influences remain visible.

The lab also produces a CWE CVSS context table from NVD CVEs mapped to each implemented CWE. Each CVE contributes one preferred CVSS v3 base score, using CVSS v3.1 before v3.0. The table stores the mean, median, and 75th percentile for each CWE, while the selected score used for weighting defaults to the median. This gives a severity-weighted view of coverage when usable CVSS data exists, so that coverage of higher-impact CWE scenarios can be interpreted separately from simple scenario count. This does not replace the primary coverage metric, because CVSS belongs to concrete vulnerabilities rather than CWE classes. The generator uses NVD-friendly request settings, delays, and retry logic because NVD rate limits unauthenticated requests, and it can use `NVD_API_KEY` if one is provided. The lab does not use local fallback scores; if NVD lookup fails or no CVSS data is available, the CWE severity context is shown as `UNKNOWN`.

Custom Semgrep rules are treated as scanner configuration, not ground truth. They may improve coverage for policy patterns such as risky workflow interpolation, broad permissions, mutable image tags, and unsafe download execution, but they are not a replacement for specialized tools such as Gitleaks for secret detection, Checkov for configuration/IaC checks, or Grype/Snyk for dependency vulnerability analysis.

## CWE Selection Notes

CWE-250 is used for the insecure container default scenario because the Dockerfile omits a `USER` directive and the CI/build container therefore executes with unnecessary root privileges. This is a better fit than CWE-16 because CWE-16 is a broad category and MITRE marks it as discouraged for vulnerability mapping.

CWE-266 is used for the token over-privilege scenario because the workflow assigns broader GitHub token privileges than the job needs. This is narrower than the earlier CWE-269 grouping and better describes the incorrect privilege assignment in the CI configuration.

CWE-732 is used for the overprivileged cloud identity scenario because the Terraform example assigns overly broad permissions to a CI/CD role. This is narrower than the earlier CWE-269 grouping and focuses on incorrect permission assignment for a resource used by the pipeline.

CWE-354 is used for mutable image tags because the deployment accepts an image reference without validating an immutable integrity value such as a digest. CWE-347 is used for unverified provenance because the deployment accepts an artifact without verifying the cryptographic signature or provenance evidence that should authenticate it. These replace the earlier broad CWE-345 grouping with more specific artifact integrity mappings.

## Mapping Rules

Findings are mapped to scenarios in this order:

1. File path containment inside a scenario directory.
2. Scenario `mappingHints.filePatterns`.
3. Scenario `mappingHints.keywords`.
4. `UNMAPPED` when no scenario can be identified.

The expected coverage table is intentionally excluded from this process.

## Result Trust Notes

The dashboard represents scanner output, not an oracle. A result is most trustworthy after a fresh full scanner run because scan startup clears prior raw outputs for known tools before wrappers execute. Starting only the dashboard initializes missing JSON files but does not erase existing scanner output. Generated files under `results/` are excluded or allowlisted where practical so tools do not report on their own previous reports. Raw findings that cannot be mapped remain visible as `UNMAPPED` rather than being hidden.

Scanner diagnostics include runtime measurements for each tool when the wrapper executed the tool binary. These measurements are useful for comparing practical scanner cost, but they depend on network state, cache state, host performance, and Docker image state.
