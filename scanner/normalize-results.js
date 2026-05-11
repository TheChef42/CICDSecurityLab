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

function weightedCoverageFor(findings, scenarios, predicate) {
  const byId = new Map(scenarios.map((scenario) => [scenario.id, scenario]));
  const totalWeight = scenarios.reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);
  const coveredIds = new Set(
    findings
      .filter((finding) => finding.mapped && predicate(finding))
      .map((finding) => finding.scenarioId)
  );
  const coveredWeight = Array.from(coveredIds).reduce((sum, scenarioId) => {
    return sum + scenarioWeight(byId.get(scenarioId) || {});
  }, 0);
  return {
    coveredWeight: Math.round(coveredWeight * 10) / 10,
    totalWeight: Math.round(totalWeight * 10) / 10,
    coveragePercent: totalWeight ? Math.round((coveredWeight / totalWeight) * 1000) / 10 : 0
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
    const covered = new Set(
      findings
        .filter((finding) => finding.tool === tool && finding.mapped)
        .map((finding) => finding.scenarioId)
    );
    perToolCoverage[tool] = {
      coveredScenarioIds: Array.from(covered).sort(),
      coveredCount: covered.size,
      totalScenarios: scenarios.length,
      coveragePercent: scenarios.length ? Math.round((covered.size / scenarios.length) * 1000) / 10 : 0,
      weightedCoverage: weightedCoverageFor(findings, scenarios, (finding) => finding.tool === tool),
      mappedFindings: findings.filter((finding) => finding.tool === tool && finding.mapped).length
    };
  }

  const perScenarioCoverage = {};
  for (const scenario of scenarios) {
    const tools = new Set(
      findings
        .filter((finding) => finding.mapped && finding.scenarioId === scenario.id)
        .map((finding) => finding.tool)
    );
    perScenarioCoverage[scenario.id] = {
      detectingTools: Array.from(tools).sort(),
      detectingToolCount: tools.size,
      totalTools: TOOLS.length,
      coveragePercent: Math.round((tools.size / TOOLS.length) * 1000) / 10,
      intendedVulnerabilityCount: scenario.intendedVulnerabilityCount || 1,
      cvss: scenario.cvss || null
    };
  }

  const mappedFindings = findings.filter((finding) => finding.mapped).length;
  const toolsReporting = Array.from(new Set(findings.map((finding) => finding.tool))).sort();
  const coveredScenarios = new Set(findings.filter((finding) => finding.mapped).map((finding) => finding.scenarioId));
  const duplicateGroups = new Set(findings.filter((finding) => finding.duplicateCount > 1).map((finding) => finding.duplicateGroupId));
  const totalIntendedVulnerabilities = scenarios.reduce((sum, scenario) => {
    return sum + (Number(scenario.intendedVulnerabilityCount) || 1);
  }, 0);

  return {
    generatedAt: new Date().toISOString(),
    scanCompleted: true,
    totalFindings: findings.length,
    mappedFindings,
    unmappedFindings: findings.length - mappedFindings,
    severityCounts,
    toolsReporting,
    totalScenarios: scenarios.length,
    totalIntendedVulnerabilities,
    totalTools: TOOLS.length,
    duplicateFindings: findings.filter((finding) => finding.duplicateCount > 1).length,
    duplicateGroups: duplicateGroups.size,
    combinedCoverage: {
      coveredScenarioIds: Array.from(coveredScenarios).sort(),
      coveredCount: coveredScenarios.size,
      coveragePercent: scenarios.length ? Math.round((coveredScenarios.size / scenarios.length) * 1000) / 10 : 0,
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

  const findings = rawFindings.map((finding, index) => {
    const mapped = mapFinding(finding, scenarios, projectDir);
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
      rawReference: mapped.rawReference || ""
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

  const diagnostics = loadDiagnostics();
  const summary = buildSummary(findings, scenarios, diagnostics);

  fs.writeFileSync(path.join(normalizedDir, "findings.json"), JSON.stringify(findings, null, 2));
  fs.writeFileSync(path.join(normalizedDir, "scenarios.json"), JSON.stringify(scenarios, null, 2));
  fs.writeFileSync(path.join(resultsDir, "diagnostics.json"), JSON.stringify(diagnostics, null, 2));
  fs.writeFileSync(path.join(resultsDir, "summary.json"), JSON.stringify(summary, null, 2));

  console.log(`Normalized ${findings.length} findings across ${scenarios.length} scenarios.`);
}

main();
