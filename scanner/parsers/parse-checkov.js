const { asArray, cleanText, firstLine, normalizeSeverity } = require("./parser-utils");

function reportsFrom(data) {
  if (Array.isArray(data)) return data;
  if (data && data.results) return [data];
  if (data && data.check_type) return [data];
  return [];
}

function parse(data) {
  const findings = [];

  for (const report of reportsFrom(data)) {
    for (const check of asArray(report.results && report.results.failed_checks)) {
      findings.push({
        tool: "checkov",
        title: cleanText(check.check_name, check.check_id || "Checkov finding"),
        severity: normalizeSeverity(check.severity || "MEDIUM"),
        file: check.file_path || check.file_abs_path || "",
        line: firstLine(check.file_line_range),
        message: cleanText(check.guideline || check.check_name || check.resource),
        ruleId: check.check_id || "checkov-check"
      });
    }
  }

  return findings;
}

module.exports = parse;
