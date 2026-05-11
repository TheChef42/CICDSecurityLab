const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

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
  if ((table.entries || []).some((entry) => {
    const confidence = String(entry.confidence || "").toUpperCase();
    const source = String(entry.source || "").toLowerCase();
    return confidence === "FALLBACK" || source.includes("fallback");
  })) {
    return false;
  }
  const generatedAt = new Date(table.generatedAt).getTime();
  if (Number.isNaN(generatedAt)) return false;
  return Date.now() - generatedAt < maxAgeDays * 24 * 60 * 60 * 1000;
}

function unavailableTable(cwes, reason) {
  return {
    generatedAt: new Date().toISOString(),
    validForDays: 30,
    cwes,
    notes: [
      "CVSS is defined for concrete vulnerabilities, not CWE classes.",
      "This table derives representative CWE severity weights from NVD CVEs mapped to each CWE.",
      "No local fallback CVSS values are used; missing lookup data is marked UNKNOWN.",
      "Scenario coverage is still calculated from mapped scanner detections."
    ],
    entries: cwes.map((cwe) => ({
      cwe,
      baseScore: null,
      severity: "UNKNOWN",
      confidence: "UNAVAILABLE",
      sampleSize: 0,
      totalMatchingCves: 0,
      fetchedCves: 0,
      complete: false,
      scoreMin: null,
      scoreMax: null,
      scoreMedian: null,
      source: "NVD CVE API grouped by CWE",
      rationale: reason
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

  const unavailable = unavailableTable(cwes, "Python CVSS generator was unavailable or failed before producing a valid table.");
  writeJson(tablePath, unavailable);
  return unavailable;
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
