export const TOOLS = ["gitleaks", "checkov", "semgrep-default", "semgrep-custom", "semgrep-combined", "trivy", "grype", "snyk"];

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

export function isCoverageEligible(finding) {
  if (Object.hasOwn(finding, "coverageEligible")) return finding.coverageEligible === true;
  return finding.mapped === true;
}

export function countMappedFindings(findings, tool, scenarioId) {
  return findings.filter(
    (finding) => isCoverageEligible(finding) && finding.tool === tool && finding.scenarioId === scenarioId
  ).length;
}

export function scenarioWeight(scenario) {
  const score = Number(scenario?.cvss?.baseScore);
  return Number.isFinite(score) && score > 0 ? score : 0;
}

export function impactLevelFromScore(score) {
  const value = Number(score);
  if (!Number.isFinite(value) || value <= 0) return "UNKNOWN";
  if (value >= 9) return "CRITICAL";
  if (value >= 7) return "HIGH";
  if (value >= 4) return "MEDIUM";
  return "LOW";
}

export function scenarioImpact(scenario) {
  const score = scenarioWeight(scenario);
  return {
    score,
    level: impactLevelFromScore(score),
    statistic: scenario?.cvss?.selectedStatistic || "n/a",
    sampleSize: Number(scenario?.cvss?.sampleSize) || 0
  };
}

export function detectionStats(findings, tool, scenario) {
  const scenarioFindings = findings.filter(
    (finding) => isCoverageEligible(finding) && finding.tool === tool && finding.scenarioId === scenario.id
  );
  const mappedRawCount = findings.filter(
    (finding) => finding.mapped && finding.tool === tool && finding.scenarioId === scenario.id
  ).length;
  const rawCount = scenarioFindings.length;
  const intendedCount = Number(scenario.intendedVulnerabilityCount) || 1;
  const creditedCount = Math.min(rawCount, intendedCount);

  return {
    rawCount,
    mappedRawCount,
    intendedCount,
    creditedCount,
    extraCount: Math.max(rawCount - creditedCount, 0),
    nonCreditedMappedCount: Math.max(mappedRawCount - rawCount, 0),
    detected: creditedCount > 0
  };
}

export function uniqueCoveredScenarioIds(findings) {
  return Array.from(
    new Set(findings.filter((finding) => isCoverageEligible(finding)).map((finding) => finding.scenarioId))
  ).sort();
}

export function scenarioTools(findings, scenarioId, selectedTools = TOOLS) {
  const selected = new Set(selectedTools);
  return Array.from(
    new Set(
      findings
        .filter((finding) => isCoverageEligible(finding) && finding.scenarioId === scenarioId && selected.has(finding.tool))
        .map((finding) => finding.tool)
    )
  ).sort();
}

export function combinedCoverage(findings, scenarios, selectedTools) {
  const selected = selectedTools.length ? selectedTools : TOOLS;
  const covered = new Set();
  const scenarioToTools = {};
  const totalWeight = scenarios.reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);

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

  const coveredWeight = coveredScenarioIds.reduce((sum, scenarioId) => {
    return sum + scenarioWeight(scenarios.find((scenario) => scenario.id === scenarioId));
  }, 0);

  return {
    selectedTools: selected,
    coveredScenarioIds,
    missedScenarioIds,
    singleToolDetections,
    overlap,
    coveragePercent: scenarios.length ? Math.round((covered.size / scenarios.length) * 1000) / 10 : 0,
    weightedCoverage: {
      coveredWeight: Math.round(coveredWeight * 10) / 10,
      totalWeight: Math.round(totalWeight * 10) / 10,
      coveragePercent: totalWeight ? Math.round((coveredWeight / totalWeight) * 1000) / 10 : 0
    }
  };
}

function combinations(items, size, start = 0, prefix = [], output = []) {
  if (prefix.length === size) {
    output.push(prefix);
    return output;
  }

  for (let index = start; index <= items.length - (size - prefix.length); index += 1) {
    combinations(items, size, index + 1, [...prefix, items[index]], output);
  }
  return output;
}

function coveredByTools(findings, scenarioIds, tools) {
  const selectedTools = new Set(tools);
  return scenarioIds.filter((scenarioId) => (
    findings.some((finding) => (
      isCoverageEligible(finding) &&
      finding.scenarioId === scenarioId &&
      selectedTools.has(finding.tool)
    ))
  ));
}

export function recommendToolSets(findings, scenarios, selectedScenarioIds, tools = TOOLS, maxRecommendations = 8) {
  const scenarioIds = selectedScenarioIds;
  const scenarioSet = new Set(scenarioIds);
  const availableTools = tools.filter((tool) => (
    findings.some((finding) => isCoverageEligible(finding) && finding.tool === tool && scenarioSet.has(finding.scenarioId))
  ));
  const scenarioToTools = Object.fromEntries(
    scenarioIds.map((scenarioId) => [scenarioId, scenarioTools(findings, scenarioId, availableTools)])
  );
  const coverableScenarioIds = scenarioIds.filter((scenarioId) => scenarioToTools[scenarioId]?.length > 0);
  const unavailableScenarioIds = scenarioIds.filter((scenarioId) => !scenarioToTools[scenarioId]?.length);

  if (!scenarioIds.length || !coverableScenarioIds.length || !availableTools.length) {
    return {
      selectedScenarioIds: scenarioIds,
      coverableScenarioIds,
      unavailableScenarioIds,
      recommendations: []
    };
  }

  const totalWeight = scenarios
    .filter((scenario) => coverableScenarioIds.includes(scenario.id))
    .reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);

  for (let size = 1; size <= availableTools.length; size += 1) {
    const recommendationSets = combinations(availableTools, size)
      .map((toolSet) => {
        const coveredScenarioIds = coveredByTools(findings, coverableScenarioIds, toolSet);
        const covered = new Set(coveredScenarioIds);
        const missedScenarioIds = coverableScenarioIds.filter((scenarioId) => !covered.has(scenarioId));
        const coveredWeight = scenarios
          .filter((scenario) => covered.has(scenario.id))
          .reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);
        const findingsCount = findings.filter((finding) => (
          isCoverageEligible(finding) &&
          covered.has(finding.scenarioId) &&
          toolSet.includes(finding.tool)
        )).length;
        return {
          tools: toolSet,
          coveredScenarioIds,
          missedScenarioIds,
          findingsCount,
          coveragePercent: coverableScenarioIds.length
            ? Math.round((coveredScenarioIds.length / coverableScenarioIds.length) * 1000) / 10
            : 0,
          weightedCoverage: {
            coveredWeight: Math.round(coveredWeight * 10) / 10,
            totalWeight: Math.round(totalWeight * 10) / 10,
            coveragePercent: totalWeight ? Math.round((coveredWeight / totalWeight) * 1000) / 10 : 0
          }
        };
      })
      .filter((recommendation) => recommendation.missedScenarioIds.length === 0);

    if (recommendationSets.length) {
      recommendationSets.sort((left, right) => (
        right.coveredScenarioIds.length - left.coveredScenarioIds.length ||
        right.weightedCoverage.coveragePercent - left.weightedCoverage.coveragePercent ||
        left.tools.join("|").localeCompare(right.tools.join("|"))
      ));

      return {
        selectedScenarioIds: scenarioIds,
        coverableScenarioIds,
        unavailableScenarioIds,
        recommendations: recommendationSets.slice(0, maxRecommendations)
      };
    }
  }

  return {
    selectedScenarioIds: scenarioIds,
    coverableScenarioIds,
    unavailableScenarioIds,
    recommendations: []
  };
}
