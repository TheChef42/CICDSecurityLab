export const EMPTY_FILTERS = {
  tool: "all",
  severity: "all",
  owaspCategory: "all",
  cwe: "all",
  scenarioId: "all",
  mapped: "all"
};

export function applyFilters(findings, filters) {
  return findings.filter((finding) => {
    if (filters.tool !== "all" && finding.tool !== filters.tool) return false;
    if (filters.severity !== "all" && finding.severity !== filters.severity) return false;
    if (filters.owaspCategory !== "all" && finding.owaspCategory !== filters.owaspCategory) return false;
    if (filters.cwe !== "all" && finding.cwe !== filters.cwe) return false;
    if (filters.scenarioId !== "all" && finding.scenarioId !== filters.scenarioId) return false;
    if (filters.mapped === "mapped" && !finding.mapped) return false;
    if (filters.mapped === "unmapped" && finding.mapped) return false;
    return true;
  });
}

export function uniqueValues(items, key) {
  return Array.from(new Set(items.map((item) => item[key]).filter(Boolean))).sort();
}
