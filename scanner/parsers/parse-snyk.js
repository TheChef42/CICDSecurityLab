const { asArray, cleanText, normalizeSeverity } = require("./parser-utils");

function collectProjects(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.vulnerabilities)) return [data];
  if (data && Array.isArray(data.projects)) return data.projects;
  return [];
}

function parse(data) {
  const findings = [];

  for (const project of collectProjects(data)) {
    for (const vuln of asArray(project.vulnerabilities)) {
      findings.push({
        tool: "snyk",
        title: cleanText(vuln.title, vuln.id || "Snyk vulnerability"),
        severity: normalizeSeverity(vuln.severity),
        file: vuln.fileName || project.displayTargetFile || project.targetFile || project.path || "",
        line: 1,
        message: cleanText(vuln.description || vuln.name || vuln.packageName),
        ruleId: vuln.id || vuln.issueId || "snyk-vulnerability"
      });
    }
  }

  return findings;
}

module.exports = parse;
