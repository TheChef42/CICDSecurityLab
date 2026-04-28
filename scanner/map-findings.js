const path = require("path");

function normalizePath(value) {
  return String(value || "")
    .replace(/\\/g, "/")
    .replace(/^file:\/\//, "")
    .replace(/^\/workspace\//, "")
    .replace(/\/+/g, "/");
}

function toRepoRelative(file, projectDir) {
  const normalized = normalizePath(file);
  if (!normalized) return "";

  const normalizedProject = normalizePath(projectDir);
  if (normalizedProject && normalized.startsWith(`${normalizedProject}/`)) {
    return normalized.slice(normalizedProject.length + 1);
  }

  if (path.isAbsolute(file || "")) {
    return normalizePath(path.relative(projectDir, file));
  }

  return normalized.replace(/^\.\//, "");
}

function wildcardToRegex(pattern) {
  const escaped = normalizePath(pattern)
    .split("*")
    .map((part) => part.replace(/[|\\{}()[\]^$+?.]/g, "\\$&"))
    .join(".*");
  return new RegExp(escaped, "i");
}

function matchesPattern(file, pattern) {
  if (!file || !pattern) return false;
  const normalizedPattern = normalizePath(pattern);
  if (normalizedPattern.includes("*")) {
    return wildcardToRegex(normalizedPattern).test(file);
  }
  return file.toLowerCase().includes(normalizedPattern.toLowerCase());
}

function applyScenario(finding, scenario) {
  return {
    ...finding,
    scenarioId: scenario.id,
    mapped: true,
    owaspCategory: scenario.owaspCategory,
    cwe: scenario.cwe
  };
}

function mapFinding(finding, scenarios, projectDir) {
  const repoFile = toRepoRelative(finding.file, projectDir);
  const searchable = [
    finding.title,
    finding.message,
    finding.ruleId,
    repoFile
  ].join(" ").toLowerCase();

  for (const scenario of scenarios) {
    const root = normalizePath(scenario.scenarioRoot);
    if (repoFile && (repoFile === root || repoFile.startsWith(`${root}/`))) {
      return applyScenario({ ...finding, file: repoFile }, scenario);
    }
  }

  for (const scenario of scenarios) {
    const hints = scenario.mappingHints || {};
    for (const pattern of hints.filePatterns || []) {
      if (matchesPattern(repoFile, pattern)) {
        return applyScenario({ ...finding, file: repoFile }, scenario);
      }
    }
  }

  for (const scenario of scenarios) {
    const hints = scenario.mappingHints || {};
    for (const keyword of hints.keywords || []) {
      if (keyword && searchable.includes(String(keyword).toLowerCase())) {
        return applyScenario({ ...finding, file: repoFile || finding.file || "" }, scenario);
      }
    }
  }

  return {
    ...finding,
    file: repoFile || finding.file || "",
    scenarioId: "UNMAPPED",
    mapped: false,
    owaspCategory: "UNMAPPED",
    cwe: "UNMAPPED"
  };
}

module.exports = {
  mapFinding,
  normalizePath,
  toRepoRelative
};
