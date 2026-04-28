const fs = require("fs");
const path = require("path");

const loadScenarios = require("./load-scenarios");

const TOOLS = ["gitleaks", "checkov", "semgrep-default", "semgrep-custom", "trivy", "grype", "snyk"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

const projectDir = process.env.PROJECT_DIR || process.cwd();
const resultsDir = process.env.RESULTS_DIR || path.join(projectDir, "results");
const rawDir = path.join(resultsDir, "raw");
const normalizedDir = path.join(resultsDir, "normalized");
const force = process.argv.includes("--force");

function writeJsonIfMissing(file, payload) {
  if (!force && fs.existsSync(file)) return;
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
    totalTools: TOOLS.length,
    combinedCoverage: {
      coveredScenarioIds: [],
      coveredCount: 0,
      coveragePercent: 0
    },
    perToolCoverage,
    perScenarioCoverage,
    diagnosticsStatus: {}
  };
}

function main() {
  fs.mkdirSync(rawDir, { recursive: true });
  fs.mkdirSync(normalizedDir, { recursive: true });

  const scenarios = loadScenarios(projectDir);

  writeJsonIfMissing(path.join(normalizedDir, "findings.json"), []);
  writeJsonIfMissing(path.join(normalizedDir, "scenarios.json"), scenarios);
  writeJsonIfMissing(path.join(resultsDir, "summary.json"), emptySummary(scenarios));
  writeJsonIfMissing(path.join(resultsDir, "diagnostics.json"), []);

  console.log(`Initialized result files in ${resultsDir}`);
}

main();
