# Methodology

This lab maps OWASP CI/CD Security Risk categories to concrete CWE-backed scenarios for repeatable academic testing.

The CWE mapping is not an official one-to-one OWASP mapping. OWASP CI/CD categories describe pipeline-level risk areas, while CWEs describe underlying software, configuration, or design weaknesses. The lab narrows broad CI/CD risks into concrete examples that can be stored in files, scanned by tools, normalized, and discussed.

All tools are treated equally. The scanner container runs every available tool against the full lab. Expected coverage is not used to decide scanner execution, parsing, finding mapping, suppression, or scoring.

Actual scanner output is the only source of coverage. A scenario is covered by a tool only when that tool emits at least one finding that maps to the scenario. If a finding cannot be mapped, it remains visible as `UNMAPPED`.

Results depend on tool version, rule configuration, scan target, network availability for vulnerability databases, and parser quality. The dashboard separates raw findings, mapped findings, coverage, and diagnostics so those influences remain visible.

## Broad CWE Notes

CWE-16 is a broad configuration category. It is suitable for the insecure container default scenario because the weakness is a configuration-level default: a CI/build container has no `USER` directive and therefore runs as root. The scenario uses CWE-16 to represent the insecure configuration pattern rather than a language-specific coding flaw.

CWE-345 is also broad. It covers insufficient verification of data authenticity, which fits two artifact integrity cases in the lab: mutable image tags and unverified provenance. Both scenarios are about accepting an artifact identity without strong authenticity guarantees. The lab splits them into `SEC09-CWE345-A` and `SEC09-CWE345-B` so the dashboard can distinguish tag mutability from missing provenance checks while keeping the underlying CWE stable.

## Mapping Rules

Findings are mapped to scenarios in this order:

1. File path containment inside a scenario directory.
2. Scenario `mappingHints.filePatterns`.
3. Scenario `mappingHints.keywords`.
4. `UNMAPPED` when no scenario can be identified.

The expected coverage table is intentionally excluded from this process.
