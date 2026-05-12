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

function roundOne(value) {
  return Math.round(value * 10) / 10;
}

function intendedCount(scenario) {
  return Math.max(Number(scenario?.intendedVulnerabilityCount) || 1, 1);
}

function coverageEligibleCount(findings, scenarioId, selectedTools = TOOLS) {
  const selected = new Set(selectedTools);
  return findings.filter((finding) => (
    isCoverageEligible(finding) &&
    finding.scenarioId === scenarioId &&
    selected.has(finding.tool)
  )).length;
}

export function scenarioCoverageCredit(findings, scenario, selectedTools = TOOLS) {
  const intended = intendedCount(scenario);
  const detected = coverageEligibleCount(findings, scenario.id, selectedTools);
  const credited = Math.min(detected, intended);
  return {
    detected,
    credited,
    intended,
    fraction: credited / intended,
    percent: roundOne((credited / intended) * 100)
  };
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
  const intended = intendedCount(scenario);
  const creditedCount = Math.min(rawCount, intended);

  return {
    rawCount,
    mappedRawCount,
    intendedCount: intended,
    creditedCount,
    extraCount: Math.max(rawCount - creditedCount, 0),
    nonCreditedMappedCount: Math.max(mappedRawCount - rawCount, 0),
    coverageFraction: creditedCount / intended,
    coveragePercent: roundOne((creditedCount / intended) * 100),
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
  const scenarioToTools = {};
  const scenarioCredits = {};
  const totalWeight = scenarios.reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);
  let totalCredit = 0;
  let coveredWeight = 0;

  for (const scenario of scenarios) {
    const tools = scenarioTools(findings, scenario.id, selected);
    const credit = scenarioCoverageCredit(findings, scenario, selected);
    scenarioToTools[scenario.id] = tools;
    scenarioCredits[scenario.id] = credit;
    totalCredit += credit.fraction;
    coveredWeight += scenarioWeight(scenario) * credit.fraction;
  }

  const coveredScenarioIds = scenarios
    .filter((scenario) => scenarioCredits[scenario.id]?.fraction > 0)
    .map((scenario) => scenario.id)
    .sort();
  const missedScenarioIds = scenarios
    .map((scenario) => scenario.id)
    .filter((id) => !scenarioCredits[id]?.fraction);
  const partiallyCoveredScenarioIds = scenarios
    .filter((scenario) => {
      const fraction = scenarioCredits[scenario.id]?.fraction || 0;
      return fraction > 0 && fraction < 1;
    })
    .map((scenario) => scenario.id)
    .sort();

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
    partiallyCoveredScenarioIds,
    scenarioCredits,
    singleToolDetections,
    overlap,
    coveragePercent: scenarios.length ? roundOne((totalCredit / scenarios.length) * 100) : 0,
    weightedCoverage: {
      coveredWeight: roundOne(coveredWeight),
      totalWeight: roundOne(totalWeight),
      coveragePercent: totalWeight ? roundOne((coveredWeight / totalWeight) * 100) : 0
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
  return scenarioIds.filter((scenarioId) => (
    coverageEligibleCount(findings, scenarioId, tools) > 0
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
        const scenarioCredits = Object.fromEntries(
          scenarios
            .filter((scenario) => coverableScenarioIds.includes(scenario.id))
            .map((scenario) => [scenario.id, scenarioCoverageCredit(findings, scenario, toolSet)])
        );
        const coveredScenarioIds = Object.entries(scenarioCredits)
          .filter(([, credit]) => credit.fraction > 0)
          .map(([scenarioId]) => scenarioId)
          .sort();
        const fullyCoveredScenarioIds = Object.entries(scenarioCredits)
          .filter(([, credit]) => credit.fraction >= 1)
          .map(([scenarioId]) => scenarioId)
          .sort();
        const partiallyCoveredScenarioIds = Object.entries(scenarioCredits)
          .filter(([, credit]) => credit.fraction > 0 && credit.fraction < 1)
          .map(([scenarioId]) => scenarioId)
          .sort();
        const covered = new Set(coveredScenarioIds);
        const missedScenarioIds = coverableScenarioIds.filter((scenarioId) => !covered.has(scenarioId));
        const totalCredit = Object.values(scenarioCredits).reduce((sum, credit) => sum + credit.fraction, 0);
        const coveredWeight = scenarios
          .filter((scenario) => Object.hasOwn(scenarioCredits, scenario.id))
          .reduce((sum, scenario) => sum + (scenarioWeight(scenario) * scenarioCredits[scenario.id].fraction), 0);
        const findingsCount = findings.filter((finding) => (
          isCoverageEligible(finding) &&
          covered.has(finding.scenarioId) &&
          toolSet.includes(finding.tool)
        )).length;
        return {
          tools: toolSet,
          coveredScenarioIds,
          fullyCoveredScenarioIds,
          partiallyCoveredScenarioIds,
          missedScenarioIds,
          scenarioCredits,
          findingsCount,
          coveragePercent: coverableScenarioIds.length
            ? roundOne((totalCredit / coverableScenarioIds.length) * 100)
            : 0,
          weightedCoverage: {
            coveredWeight: roundOne(coveredWeight),
            totalWeight: roundOne(totalWeight),
            coveragePercent: totalWeight ? roundOne((coveredWeight / totalWeight) * 100) : 0
          }
        };
      })
      .filter((recommendation) => recommendation.fullyCoveredScenarioIds.length === coverableScenarioIds.length);

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
