const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const FALLBACK_ENTRIES = {
  "CWE-16": { baseScore: 6.5, severity: "MEDIUM", confidence: "FALLBACK" },
  "CWE-78": { baseScore: 9.1, severity: "CRITICAL", confidence: "FALLBACK" },
  "CWE-269": { baseScore: 8.8, severity: "HIGH", confidence: "FALLBACK" },
  "CWE-345": { baseScore: 7.4, severity: "HIGH", confidence: "FALLBACK" },
  "CWE-494": { baseScore: 8.1, severity: "HIGH", confidence: "FALLBACK" },
  "CWE-532": { baseScore: 5.3, severity: "MEDIUM", confidence: "FALLBACK" },
  "CWE-798": { baseScore: 7.5, severity: "HIGH", confidence: "FALLBACK" },
  "CWE-829": { baseScore: 8.0, severity: "HIGH", confidence: "FALLBACK" }
};

function readJson(file) {
  if (!fs.existsSync(file)) return null;
  const content = fs.readFileSync(file, "utf8").trim();
  return content ? JSON.parse(content) : null;
}

function currentCwes(scenarios) {
  return Array.from(new Set(scenarios.map((scenario) => scenario.cwe).filter(Boolean))).sort();
}

function sameCwes(left, right) {
  return JSON.stringify(left || []) === JSON.stringify(right || []);
}

function isFresh(table, cwes, maxAgeDays = 30) {
  if (!table || !sameCwes(table.cwes, cwes) || !table.generatedAt) return false;
  const generatedAt = new Date(table.generatedAt).getTime();
  if (Number.isNaN(generatedAt)) return false;
  return Date.now() - generatedAt < maxAgeDays * 24 * 60 * 60 * 1000;
}

function fallbackTable(cwes) {
  return {
    generatedAt: new Date().toISOString(),
    validForDays: 30,
    cwes,
    notes: [
      "CVSS is defined for concrete vulnerabilities, not CWE classes.",
      "This table provides representative CWE severity weights for lab analysis.",
      "Scenario coverage is still calculated from mapped scanner detections."
    ],
    entries: cwes.map((cwe) => ({
      cwe,
      baseScore: FALLBACK_ENTRIES[cwe]?.baseScore || 0,
      severity: FALLBACK_ENTRIES[cwe]?.severity || "UNKNOWN",
      confidence: FALLBACK_ENTRIES[cwe]?.confidence || "UNKNOWN",
      sampleSize: 0,
      source: "Node fallback representative CWE severity table"
    }))
  };
}

function writeJson(file, payload) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`);
}

function runPythonGenerator(projectDir, tablePath) {
  const script = path.join(projectDir, "scanner", "cwe-cvss-weights.py");
  const candidates = [process.env.PYTHON_BIN, "python3", "python"].filter(Boolean);
  for (const python of candidates) {
    const result = spawnSync(
      python,
      [script, "--project-dir", projectDir, "--output", tablePath],
      { encoding: "utf8", env: process.env }
    );
    if (result.status === 0 && fs.existsSync(tablePath)) return readJson(tablePath);
  }
  return null;
}

function ensureCweCvssTable(projectDir, resultsDir, scenarios) {
  const tablePath = path.join(resultsDir, "normalized", "cwe-cvss.json");
  const cwes = currentCwes(scenarios);
  const existing = readJson(tablePath);
  if (isFresh(existing, cwes)) return existing;

  const generated = runPythonGenerator(projectDir, tablePath);
  if (generated && sameCwes(generated.cwes, cwes)) return generated;

  const fallback = fallbackTable(cwes);
  writeJson(tablePath, fallback);
  return fallback;
}

function enrichScenariosWithCvss(scenarios, table) {
  const byCwe = new Map((table?.entries || []).map((entry) => [entry.cwe, entry]));
  return scenarios.map((scenario) => ({
    ...scenario,
    cvss: byCwe.get(scenario.cwe) || null
  }));
}

module.exports = {
  ensureCweCvssTable,
  enrichScenariosWithCvss
};
