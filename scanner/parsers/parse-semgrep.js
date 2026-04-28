const { asArray, cleanText, firstLine, normalizeSeverity } = require("./parser-utils");

function parse(data, tool = "semgrep") {
  return asArray(data.results).map((finding) => {
    const extra = finding.extra || {};
    return {
      tool,
      title: cleanText(extra.metadata && extra.metadata.title, finding.check_id || "Semgrep finding"),
      severity: normalizeSeverity(extra.severity),
      file: finding.path || "",
      line: firstLine(finding.start && finding.start.line),
      message: cleanText(extra.message || finding.check_id),
      ruleId: finding.check_id || "semgrep-rule"
    };
  });
}

module.exports = parse;
