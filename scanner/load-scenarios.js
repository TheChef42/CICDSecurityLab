const fs = require("fs");
const path = require("path");

const SCENARIO_ORDER = [
  "SEC03-CWE494",
  "SEC03-CWE829",
  "SEC04-CWE78",
  "SEC04-CWE269",
  "SEC06-CWE798",
  "SEC06-CWE532",
  "SEC07-CWE16",
  "SEC07-CWE269",
  "SEC09-CWE345-A",
  "SEC09-CWE345-B"
];

function normalizePath(value) {
  return String(value || "").replace(/\\/g, "/").replace(/^\/workspace\//, "");
}

function walk(dir, matches = []) {
  if (!fs.existsSync(dir)) return matches;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, matches);
    } else if (entry.isFile() && entry.name === "metadata.json") {
      matches.push(full);
    }
  }
  return matches;
}

function loadScenarios(projectDir = process.cwd()) {
  const scenarioRoot = path.join(projectDir, "scenarios");
  const files = walk(scenarioRoot);

  const scenarios = files.map((file) => {
    const metadata = JSON.parse(fs.readFileSync(file, "utf8"));
    const rootAbs = path.dirname(file);
    const rootRel = normalizePath(path.relative(projectDir, rootAbs));
    return {
      ...metadata,
      scenarioRoot: rootRel,
      metadataPath: normalizePath(path.relative(projectDir, file))
    };
  });

  const orderIndex = new Map(SCENARIO_ORDER.map((id, index) => [id, index]));
  scenarios.sort((a, b) => {
    const left = orderIndex.has(a.id) ? orderIndex.get(a.id) : Number.MAX_SAFE_INTEGER;
    const right = orderIndex.has(b.id) ? orderIndex.get(b.id) : Number.MAX_SAFE_INTEGER;
    return left - right || a.id.localeCompare(b.id);
  });

  return scenarios;
}

loadScenarios.SCENARIO_ORDER = SCENARIO_ORDER;
module.exports = loadScenarios;
