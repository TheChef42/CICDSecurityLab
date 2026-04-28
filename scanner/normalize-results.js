const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const loadScenarios = require("./load-scenarios");
const { mapFinding } = require("./map-findings");

const parsers = {
  trivy: require("./parsers/parse-trivy"),
  snyk: require("./parsers/parse-snyk"),
  semgrep: require("./parsers/parse-semgrep"),
  gitleaks: require("./parsers/parse-gitleaks"),
  checkov: require("./parsers/parse-checkov"),
  grype: require("./parsers/parse-grype")
};

const TOOLS = ["gitleaks", "checkov", "semgrep", "trivy", "grype", "snyk"];
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

function loadDiagnostics() {
  const diagnostics = [];
  if (fs.existsSync(diagnosticsDir)) {
    for (const entry of fs.readdirSync(diagnosticsDir)) {
      if (!entry.endsWith(".json")) continue;
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
      coveragePercent: Math.round((tools.size / TOOLS.length) * 1000) / 10
    };
  }

  const mappedFindings = findings.filter((finding) => finding.mapped).length;
  const toolsReporting = Array.from(new Set(findings.map((finding) => finding.tool))).sort();
  const coveredScenarios = new Set(findings.filter((finding) => finding.mapped).map((finding) => finding.scenarioId));

  return {
    generatedAt: new Date().toISOString(),
    scanCompleted: true,
    totalFindings: findings.length,
    mappedFindings,
    unmappedFindings: findings.length - mappedFindings,
    severityCounts,
    toolsReporting,
    totalScenarios: scenarios.length,
    totalTools: TOOLS.length,
    combinedCoverage: {
      coveredScenarioIds: Array.from(coveredScenarios).sort(),
      coveredCount: coveredScenarios.size,
      coveragePercent: scenarios.length ? Math.round((coveredScenarios.size / scenarios.length) * 1000) / 10 : 0
    },
    perToolCoverage,
    perScenarioCoverage,
    diagnosticsStatus: Object.fromEntries(diagnostics.map((item) => [item.tool, item.status]))
  };
}

function main() {
  const scenarios = loadScenarios(projectDir);
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

  const diagnostics = loadDiagnostics();
  const summary = buildSummary(findings, scenarios, diagnostics);

  fs.writeFileSync(path.join(normalizedDir, "findings.json"), JSON.stringify(findings, null, 2));
  fs.writeFileSync(path.join(normalizedDir, "scenarios.json"), JSON.stringify(scenarios, null, 2));
  fs.writeFileSync(path.join(resultsDir, "diagnostics.json"), JSON.stringify(diagnostics, null, 2));
  fs.writeFileSync(path.join(resultsDir, "summary.json"), JSON.stringify(summary, null, 2));

  console.log(`Normalized ${findings.length} findings across ${scenarios.length} scenarios.`);
}

main();
