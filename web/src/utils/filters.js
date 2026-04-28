export const EMPTY_FILTERS = {
  tool: [],
  severity: [],
  owaspCategory: [],
  cwe: [],
  scenarioId: [],
  mapped: []
};

function matchesSelected(value, selected) {
  return !selected.length || selected.includes(value);
}

export function applyFilters(findings, filters) {
  return findings.filter((finding) => {
    if (!matchesSelected(finding.tool, filters.tool)) return false;
    if (!matchesSelected(finding.severity, filters.severity)) return false;
    if (!matchesSelected(finding.owaspCategory, filters.owaspCategory)) return false;
    if (!matchesSelected(finding.cwe, filters.cwe)) return false;
    if (!matchesSelected(finding.scenarioId, filters.scenarioId)) return false;
    if (filters.mapped.length === 1 && filters.mapped.includes("mapped") && !finding.mapped) return false;
    if (filters.mapped.length === 1 && filters.mapped.includes("unmapped") && finding.mapped) return false;
    return true;
  });
}

export function uniqueValues(items, key) {
  return Array.from(new Set(items.map((item) => item[key]).filter(Boolean))).sort();
}
