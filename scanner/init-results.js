const fs = require("fs");
const path = require("path");

const loadScenarios = require("./load-scenarios");

const TOOLS = ["gitleaks", "checkov", "semgrep-default", "semgrep-custom", "semgrep-combined", "trivy", "grype", "snyk"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

const projectDir = process.env.PROJECT_DIR || process.cwd();
const resultsDir = process.env.RESULTS_DIR || path.join(projectDir, "results");
const rawDir = path.join(resultsDir, "raw");
const normalizedDir = path.join(resultsDir, "normalized");
const diagnosticsDir = path.join(rawDir, "diagnostics");
const logDir = path.join(rawDir, "logs");
const force = process.argv.includes("--force");
const resetRun = process.argv.includes("--reset-run");

function writeJsonIfMissing(file, payload) {
  if (!force && fs.existsSync(file)) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`);
}

function writeJson(file, payload) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`);
}

function emptySummary(scenarios) {
  const perToolCoverage = Object.fromEntries(
    TOOLS.map((tool) => [
      tool,
      {
        coveredScenarioIds: [],
        coveredCount: 0,
        totalScenarios: scenarios.length,
        coveragePercent: 0,
        mappedFindings: 0
      }
    ])
  );

  const perScenarioCoverage = Object.fromEntries(
    scenarios.map((scenario) => [
      scenario.id,
      {
        detectingTools: [],
        detectingToolCount: 0,
        totalTools: TOOLS.length,
        coveragePercent: 0
      }
    ])
  );

  return {
    generatedAt: null,
    scanCompleted: false,
    totalFindings: 0,
    mappedFindings: 0,
    unmappedFindings: 0,
    severityCounts: Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])),
    toolsReporting: [],
    totalScenarios: scenarios.length,
    totalIntendedVulnerabilities: scenarios.reduce((sum, scenario) => sum + (Number(scenario.intendedVulnerabilityCount) || 1), 0),
    totalTools: TOOLS.length,
    duplicateFindings: 0,
    duplicateGroups: 0,
    combinedCoverage: {
      coveredScenarioIds: [],
      coveredCount: 0,
      coveragePercent: 0,
      weightedCoverage: {
        coveredWeight: 0,
        totalWeight: Math.round(scenarios.reduce((sum, scenario) => sum + (Number(scenario.cvss?.baseScore) || 0), 0) * 10) / 10,
        coveragePercent: 0
      }
    },
    perToolCoverage,
    perScenarioCoverage,
    diagnosticsStatus: {}
  };
}

function main() {
  fs.mkdirSync(rawDir, { recursive: true });
  fs.mkdirSync(normalizedDir, { recursive: true });
  fs.mkdirSync(diagnosticsDir, { recursive: true });
  fs.mkdirSync(logDir, { recursive: true });

  const scenarios = loadScenarios(projectDir);

  if (resetRun) {
    for (const tool of TOOLS) {
      for (const file of [
        path.join(rawDir, `${tool}.json`),
        path.join(diagnosticsDir, `${tool}.json`),
        path.join(logDir, `${tool}.log`)
      ]) {
        if (fs.existsSync(file)) fs.rmSync(file);
      }
    }
  }

  writeJsonIfMissing(path.join(normalizedDir, "findings.json"), []);
  writeJson(path.join(normalizedDir, "scenarios.json"), scenarios);
  writeJsonIfMissing(path.join(normalizedDir, "cwe-cvss.json"), {
    generatedAt: null,
    validForDays: 30,
    cwes: [],
    notes: [],
    entries: []
  });
  writeJsonIfMissing(path.join(resultsDir, "summary.json"), emptySummary(scenarios));
  writeJsonIfMissing(path.join(resultsDir, "diagnostics.json"), []);

  console.log(`Initialized result files in ${resultsDir}`);
}

main();
