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

  if (normalized.startsWith("/scenarios/")) {
    return normalized.slice(1);
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

function pathMatchesKnownFiles(file, files) {
  const normalizedFile = normalizePath(file).toLowerCase();
  return (files || []).some((candidate) => normalizedFile === normalizePath(candidate).toLowerCase());
}

function evidenceRoleFor(file, scenario) {
  const repoFile = normalizePath(file);
  const root = normalizePath(scenario.scenarioRoot);
  if (!repoFile) return "unknown";
  if (pathMatchesKnownFiles(repoFile, scenario.vulnerableFiles)) return "vulnerable";
  if (pathMatchesKnownFiles(repoFile, scenario.fixedFiles)) return "fixed";
  if (root && repoFile.startsWith(`${root}/vulnerable/`)) return "vulnerable";
  if (root && repoFile.startsWith(`${root}/fixed/`)) return "fixed";
  if (root && (repoFile === root || repoFile.startsWith(`${root}/`))) return "scenario-support";
  return "external";
}

function applyScenario(finding, scenario, mappingMethod) {
  const evidenceRole = evidenceRoleFor(finding.file, scenario);
  return {
    ...finding,
    scenarioId: scenario.id,
    mapped: true,
    mappingMethod,
    evidenceRole,
    coverageEligible: evidenceRole === "vulnerable",
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
      return applyScenario({ ...finding, file: repoFile }, scenario, "scenario-path");
    }
  }

  for (const scenario of scenarios) {
    const hints = scenario.mappingHints || {};
    for (const pattern of hints.filePatterns || []) {
      if (matchesPattern(repoFile, pattern)) {
        return applyScenario({ ...finding, file: repoFile }, scenario, "file-pattern");
      }
    }
  }

  if (!repoFile || repoFile.startsWith("scenarios/")) {
    for (const scenario of scenarios) {
      const hints = scenario.mappingHints || {};
      for (const keyword of hints.keywords || []) {
        if (keyword && searchable.includes(String(keyword).toLowerCase())) {
          return applyScenario({ ...finding, file: repoFile || finding.file || "" }, scenario, "keyword");
        }
      }
    }
  }

  return {
    ...finding,
    file: repoFile || finding.file || "",
    scenarioId: "UNMAPPED",
    mapped: false,
    mappingMethod: "unmapped",
    evidenceRole: "unmapped",
    coverageEligible: false,
    owaspCategory: "UNMAPPED",
    cwe: "UNMAPPED"
  };
}

module.exports = {
  mapFinding,
  normalizePath,
  toRepoRelative
};
