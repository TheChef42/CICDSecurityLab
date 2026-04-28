const { asArray, cleanText, firstLine } = require("./parser-utils");

function parse(data) {
  const entries = Array.isArray(data) ? data : asArray(data.findings || data.Findings || data.leaks);

  return entries.map((finding) => ({
    tool: "gitleaks",
    title: cleanText(finding.Description, "Secret detected"),
    severity: "HIGH",
    file: finding.File || finding.file || "",
    line: firstLine(finding.StartLine || finding.line),
    message: cleanText(finding.Line || finding.Match || "Secret-like value detected by Gitleaks"),
    ruleId: finding.RuleID || finding.rule || "gitleaks-rule"
  }));
}

module.exports = parse;
