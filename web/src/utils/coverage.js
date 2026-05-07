export const TOOLS = ["gitleaks", "checkov", "semgrep-default", "semgrep-custom", "semgrep-combined", "trivy", "grype", "snyk"];

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

export function countMappedFindings(findings, tool, scenarioId) {
  return findings.filter(
    (finding) => finding.mapped && finding.tool === tool && finding.scenarioId === scenarioId
  ).length;
}

export function scenarioTools(findings, scenarioId, selectedTools = TOOLS) {
  const selected = new Set(selectedTools);
  return Array.from(
    new Set(
      findings
        .filter((finding) => finding.mapped && finding.scenarioId === scenarioId && selected.has(finding.tool))
        .map((finding) => finding.tool)
    )
  ).sort();
}

export function combinedCoverage(findings, scenarios, selectedTools) {
  const selected = selectedTools.length ? selectedTools : TOOLS;
  const covered = new Set();
  const scenarioToTools = {};

  for (const scenario of scenarios) {
    const tools = scenarioTools(findings, scenario.id, selected);
    scenarioToTools[scenario.id] = tools;
    if (tools.length > 0) covered.add(scenario.id);
  }

  const coveredScenarioIds = Array.from(covered).sort();
  const missedScenarioIds = scenarios
    .map((scenario) => scenario.id)
    .filter((id) => !covered.has(id));

  const singleToolDetections = Object.entries(scenarioToTools)
    .filter(([, tools]) => tools.length === 1)
    .map(([scenarioId, tools]) => ({ scenarioId, tool: tools[0] }));

  const overlap = [];
  for (let i = 0; i < selected.length; i += 1) {
    for (let j = i + 1; j < selected.length; j += 1) {
      const left = selected[i];
      const right = selected[j];
      const shared = scenarios
        .filter((scenario) => {
          const tools = scenarioToTools[scenario.id] || [];
          return tools.includes(left) && tools.includes(right);
        })
        .map((scenario) => scenario.id);
      overlap.push({ pair: `${left} + ${right}`, sharedScenarioIds: shared });
    }
  }

  return {
    selectedTools: selected,
    coveredScenarioIds,
    missedScenarioIds,
    singleToolDetections,
    overlap,
    coveragePercent: scenarios.length ? Math.round((covered.size / scenarios.length) * 1000) / 10 : 0
  };
}
