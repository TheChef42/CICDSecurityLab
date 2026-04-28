const { asArray, cleanText, normalizeSeverity } = require("./parser-utils");

function locationFor(match) {
  const locations = asArray(match.artifact && match.artifact.locations);
  const first = locations[0] || {};
  return first.path || first.realPath || "";
}

function parse(data) {
  return asArray(data.matches).map((match) => {
    const vuln = match.vulnerability || {};
    const artifact = match.artifact || {};
    return {
      tool: "grype",
      title: cleanText(vuln.description || vuln.id, `${artifact.name || "package"} vulnerability`),
      severity: normalizeSeverity(vuln.severity),
      file: locationFor(match) || artifact.name || "",
      line: 1,
      message: cleanText(`${artifact.name || "package"} ${artifact.version || ""} matched ${vuln.id || "a vulnerability"}`),
      ruleId: vuln.id || "grype-vulnerability"
    };
  });
}

module.exports = parse;
