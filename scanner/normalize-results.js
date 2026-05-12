const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const loadScenarios = require("./load-scenarios");
const { ensureCweCvssTable, enrichScenariosWithCvss } = require("./cwe-cvss");
const { mapFinding } = require("./map-findings");

const parsers = {
  trivy: require("./parsers/parse-trivy"),
  snyk: require("./parsers/parse-snyk"),
  "semgrep-default": (raw) => require("./parsers/parse-semgrep")(raw, "semgrep-default"),
  "semgrep-custom": (raw) => require("./parsers/parse-semgrep")(raw, "semgrep-custom"),
  "semgrep-combined": (raw) => require("./parsers/parse-semgrep")(raw, "semgrep-combined"),
  gitleaks: require("./parsers/parse-gitleaks"),
  checkov: require("./parsers/parse-checkov"),
  grype: require("./parsers/parse-grype")
};

const TOOLS = ["gitleaks", "checkov", "semgrep-default", "semgrep-custom", "semgrep-combined", "trivy", "grype", "snyk"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

const projectDir = process.env.PROJECT_DIR || process.cwd();
const resultsDir = process.env.RESULTS_DIR || path.join(projectDir, "results");
const rawDir = path.join(resultsDir, "raw");
const normalizedDir = path.join(resultsDir, "normalized");
const diagnosticsDir = path.join(rawDir, "diagnostics");

fs.mkdirSync(rawDir, { recursive: true });
fs.mkdirSync(normalizedDir, { recursive: true });

function readJson(file) {
  if (!fs.existsSync(file)) return null;
  const content = fs.readFileSync(file, "utf8").trim();
  if (!content) return null;
  return JSON.parse(content);
}

function relativeResultPath(file) {
  return path.relative(projectDir, file).replace(/\\/g, "/");
}

function findingId(finding, index) {
  const seed = [
    finding.tool,
    finding.ruleId,
    finding.file,
    finding.line,
    finding.title,
    finding.message,
    index
  ].join("|");
  return crypto.createHash("sha1").update(seed).digest("hex").slice(0, 16);
}

function duplicateSeed(finding) {
  return [
    finding.tool,
    finding.scenarioId,
    finding.file,
    finding.line,
    finding.ruleId,
    finding.message
  ].join("|");
}

function scenarioWeight(scenario) {
  const score = Number(scenario.cvss?.baseScore);
  return Number.isFinite(score) && score > 0 ? score : 0;
}

function roundOne(value) {
  return Math.round(value * 10) / 10;
}

function intendedCount(scenario) {
  return Math.max(Number(scenario?.intendedVulnerabilityCount) || 1, 1);
}

function coverageCreditFor(findings, scenario, predicate) {
  const detected = findings.filter((finding) => (
    finding.coverageEligible &&
    finding.scenarioId === scenario.id &&
    predicate(finding)
  )).length;
  const intended = intendedCount(scenario);
  const credited = Math.min(detected, intended);
  return {
    detected,
    credited,
    intended,
    fraction: credited / intended,
    percent: roundOne((credited / intended) * 100)
  };
}

function impactLevelFromScore(score) {
  const value = Number(score);
  if (!Number.isFinite(value) || value <= 0) return "UNKNOWN";
  if (value >= 9) return "CRITICAL";
  if (value >= 7) return "HIGH";
  if (value >= 4) return "MEDIUM";
  return "LOW";
}

function weightedCoverageFor(findings, scenarios, predicate) {
  const totalWeight = scenarios.reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);
  const coveredWeight = scenarios.reduce((sum, scenario) => {
    const credit = coverageCreditFor(findings, scenario, predicate);
    return sum + (scenarioWeight(scenario) * credit.fraction);
  }, 0);
  return {
    coveredWeight: roundOne(coveredWeight),
    totalWeight: roundOne(totalWeight),
    coveragePercent: totalWeight ? roundOne((coveredWeight / totalWeight) * 100) : 0
  };
}

function loadDiagnostics() {
  const diagnostics = [];
  if (fs.existsSync(diagnosticsDir)) {
    const allowedDiagnostics = new Set(TOOLS.map((tool) => `${tool}.json`));
    for (const entry of fs.readdirSync(diagnosticsDir)) {
      if (!entry.endsWith(".json")) continue;
      if (!allowedDiagnostics.has(entry)) continue;
      try {
        diagnostics.push(readJson(path.join(diagnosticsDir, entry)));
      } catch (error) {
        diagnostics.push({
          tool: entry.replace(/\.json$/, ""),
          status: "ERROR",
          message: `Could not parse diagnostic JSON: ${error.message}`,
          rawOutputPath: null
        });
      }
    }
  }

  const seen = new Set(diagnostics.filter(Boolean).map((item) => item.tool));
  for (const tool of TOOLS) {
    if (!seen.has(tool)) {
      diagnostics.push({
        tool,
        status: "WARN",
        message: "No diagnostic record was produced for this tool.",
        rawOutputPath: null
      });
    }
  }

  return diagnostics.filter(Boolean).sort((a, b) => TOOLS.indexOf(a.tool) - TOOLS.indexOf(b.tool));
}

function buildSummary(findings, scenarios, diagnostics) {
  const severityCounts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  for (const finding of findings) {
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
  }

  const perToolCoverage = {};
  for (const tool of TOOLS) {
    const scenarioCredits = Object.fromEntries(
      scenarios.map((scenario) => [scenario.id, coverageCreditFor(findings, scenario, (finding) => finding.tool === tool)])
    );
    const coveredScenarioIds = scenarios
      .filter((scenario) => scenarioCredits[scenario.id].fraction > 0)
      .map((scenario) => scenario.id)
      .sort();
    const coveredScenarioEquivalents = scenarios.reduce((sum, scenario) => {
      return sum + scenarioCredits[scenario.id].fraction;
    }, 0);
    perToolCoverage[tool] = {
      coveredScenarioIds,
      coveredCount: roundOne(coveredScenarioEquivalents),
      totalScenarios: scenarios.length,
      coveragePercent: scenarios.length ? roundOne((coveredScenarioEquivalents / scenarios.length) * 100) : 0,
      weightedCoverage: weightedCoverageFor(findings, scenarios, (finding) => finding.tool === tool),
      scenarioCredits,
      mappedFindings: findings.filter((finding) => finding.tool === tool && finding.mapped).length,
      coverageEligibleFindings: findings.filter((finding) => finding.tool === tool && finding.coverageEligible).length
    };
  }

  const perScenarioCoverage = {};
  for (const scenario of scenarios) {
    const toolCredits = Object.fromEntries(
      TOOLS.map((tool) => [tool, coverageCreditFor(findings, scenario, (finding) => finding.tool === tool)])
    );
    const totalToolCredit = Object.values(toolCredits).reduce((sum, credit) => sum + credit.fraction, 0);
    const tools = new Set(
      findings
        .filter((finding) => finding.coverageEligible && finding.scenarioId === scenario.id)
        .map((finding) => finding.tool)
    );
    perScenarioCoverage[scenario.id] = {
      detectingTools: Array.from(tools).sort(),
      detectingToolCount: tools.size,
      totalTools: TOOLS.length,
      coveragePercent: TOOLS.length ? roundOne((totalToolCredit / TOOLS.length) * 100) : 0,
      toolCredits,
      intendedVulnerabilityCount: scenario.intendedVulnerabilityCount || 1,
      cvss: scenario.cvss || null
    };
  }

  const mappedFindings = findings.filter((finding) => finding.mapped).length;
  const coverageEligibleFindings = findings.filter((finding) => finding.coverageEligible).length;
  const toolsReporting = Array.from(new Set(findings.map((finding) => finding.tool))).sort();
  const scenarioCredits = Object.fromEntries(
    scenarios.map((scenario) => [scenario.id, coverageCreditFor(findings, scenario, () => true)])
  );
  const coveredScenarioIds = scenarios
    .filter((scenario) => scenarioCredits[scenario.id].fraction > 0)
    .map((scenario) => scenario.id)
    .sort();
  const partialScenarioIds = scenarios
    .filter((scenario) => {
      const fraction = scenarioCredits[scenario.id].fraction;
      return fraction > 0 && fraction < 1;
    })
    .map((scenario) => scenario.id)
    .sort();
  const coveredScenarioEquivalents = Object.values(scenarioCredits).reduce((sum, credit) => sum + credit.fraction, 0);
  const duplicateGroups = new Set(findings.filter((finding) => finding.duplicateCount > 1).map((finding) => finding.duplicateGroupId));
  const totalIntendedVulnerabilities = scenarios.reduce((sum, scenario) => {
    return sum + (Number(scenario.intendedVulnerabilityCount) || 1);
  }, 0);

  return {
    generatedAt: new Date().toISOString(),
    scanCompleted: true,
    totalFindings: findings.length,
    mappedFindings,
    coverageEligibleFindings,
    unmappedFindings: findings.length - mappedFindings,
    severityCounts,
    toolsReporting,
    totalScenarios: scenarios.length,
    totalIntendedVulnerabilities,
    totalTools: TOOLS.length,
    duplicateFindings: findings.filter((finding) => finding.duplicateCount > 1).length,
    duplicateGroups: duplicateGroups.size,
    extraScenarioFindings: findings.filter((finding) => finding.coverageExtra).length,
    combinedCoverage: {
      coveredScenarioIds,
      partiallyCoveredScenarioIds: partialScenarioIds,
      coveredCount: roundOne(coveredScenarioEquivalents),
      totalScenarios: scenarios.length,
      scenarioCredits,
      coveragePercent: scenarios.length ? roundOne((coveredScenarioEquivalents / scenarios.length) * 100) : 0,
      weightedCoverage: weightedCoverageFor(findings, scenarios, () => true)
    },
    perToolCoverage,
    perScenarioCoverage,
    diagnosticsStatus: Object.fromEntries(diagnostics.map((item) => [item.tool, item.status]))
  };
}

function main() {
  const baseScenarios = loadScenarios(projectDir);
  const cweCvssTable = ensureCweCvssTable(projectDir, resultsDir, baseScenarios);
  const scenarios = enrichScenariosWithCvss(baseScenarios, cweCvssTable);
  const rawFindings = [];

  for (const tool of TOOLS) {
    const rawFile = path.join(rawDir, `${tool}.json`);
    const parser = parsers[tool];
    try {
      const raw = readJson(rawFile);
      if (!raw) continue;
      const parsed = parser(raw).map((finding) => ({
        ...finding,
        rawReference: relativeResultPath(rawFile)
      }));
      rawFindings.push(...parsed);
    } catch (error) {
      rawFindings.push({
        tool,
        title: "Parser error",
        severity: "UNKNOWN",
        file: "",
        line: 1,
        message: `Could not parse ${tool} output: ${error.message}`,
        ruleId: "parser-error",
        rawReference: relativeResultPath(rawFile)
      });
    }
  }

  const scenariosById = new Map(scenarios.map((scenario) => [scenario.id, scenario]));

  const findings = rawFindings.map((finding, index) => {
    const mapped = mapFinding(finding, scenarios, projectDir);
    const scenario = scenariosById.get(mapped.scenarioId);
    const cvssScore = scenarioWeight(scenario || {});
    return {
      id: findingId(mapped, index),
      tool: mapped.tool,
      scenarioId: mapped.scenarioId,
      mapped: mapped.mapped,
      owaspCategory: mapped.owaspCategory,
      cwe: mapped.cwe,
      title: mapped.title || "Unmapped finding",
      severity: mapped.severity || "UNKNOWN",
      file: mapped.file || "",
      line: mapped.line || 1,
      message: mapped.message || "",
      ruleId: mapped.ruleId || "",
      rawReference: mapped.rawReference || "",
      mappingMethod: mapped.mappingMethod || "unmapped",
      evidenceRole: mapped.evidenceRole || "unknown",
      coverageEligible: Boolean(mapped.coverageEligible),
      coverageExclusionReason: mapped.mapped && !mapped.coverageEligible
        ? `Mapped to ${mapped.scenarioId}, but not counted for coverage because the finding is in ${mapped.evidenceRole} evidence rather than the vulnerable example.`
        : "",
      impactScore: mapped.mapped ? cvssScore : 0,
      impactLevel: mapped.mapped ? impactLevelFromScore(cvssScore) : "UNMAPPED",
      impactSource: mapped.mapped ? (scenario?.cvss?.selectedStatistic || "scenario CVSS") : "UNMAPPED",
      impactRationale: mapped.mapped
        ? `Impact is inherited from ${mapped.scenarioId} (${scenario?.cwe || mapped.cwe}) using the selected CVSS statistic.`
        : "Finding is unmapped, so no scenario CVSS impact can be assigned."
    };
  });

  const duplicates = new Map();
  for (const finding of findings) {
    const seed = duplicateSeed(finding);
    const groupId = crypto.createHash("sha1").update(seed).digest("hex").slice(0, 12);
    if (!duplicates.has(groupId)) duplicates.set(groupId, []);
    duplicates.get(groupId).push(finding);
  }
  for (const [groupId, group] of duplicates.entries()) {
    group.forEach((finding, index) => {
      finding.duplicateGroupId = groupId;
      finding.duplicateIndex = index + 1;
      finding.duplicateCount = group.length;
      finding.duplicate = group.length > 1;
    });
  }

  const toolScenarioGroups = new Map();
  for (const finding of findings) {
    if (!finding.coverageEligible) continue;
    const key = `${finding.tool}|${finding.scenarioId}`;
    if (!toolScenarioGroups.has(key)) toolScenarioGroups.set(key, []);
    toolScenarioGroups.get(key).push(finding);
  }

  for (const [, group] of toolScenarioGroups.entries()) {
    const scenario = scenariosById.get(group[0].scenarioId);
    const intendedCount = Number(scenario?.intendedVulnerabilityCount) || 1;
    group
      .sort((left, right) => (
        (left.file || "").localeCompare(right.file || "") ||
        (Number(left.line) || 0) - (Number(right.line) || 0) ||
        (left.ruleId || "").localeCompare(right.ruleId || "")
      ))
      .forEach((finding, index) => {
        finding.coverageFindingIndex = index + 1;
        finding.coverageFindingCount = group.length;
        finding.coverageCredited = index < intendedCount;
        finding.coverageExtra = index >= intendedCount;
        finding.coverageExtraReason = finding.coverageExtra
          ? `Additional raw finding for ${finding.scenarioId}; coverage credit is capped at ${intendedCount} intended vulnerability instance(s).`
          : "";
      });
  }

  const diagnostics = loadDiagnostics();
  const summary = buildSummary(findings, scenarios, diagnostics);

  fs.writeFileSync(path.join(normalizedDir, "findings.json"), JSON.stringify(findings, null, 2));
  fs.writeFileSync(path.join(normalizedDir, "scenarios.json"), JSON.stringify(scenarios, null, 2));
  fs.writeFileSync(path.join(resultsDir, "diagnostics.json"), JSON.stringify(diagnostics, null, 2));
  fs.writeFileSync(path.join(resultsDir, "summary.json"), JSON.stringify(summary, null, 2));

  console.log(`Normalized ${findings.length} findings across ${scenarios.length} scenarios.`);
}

main();
