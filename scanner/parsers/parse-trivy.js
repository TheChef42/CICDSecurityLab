const { asArray, cleanText, firstLine, normalizeSeverity } = require("./parser-utils");

function parse(data) {
  const findings = [];

  for (const result of asArray(data.Results)) {
    const target = result.Target || "";

    for (const vuln of asArray(result.Vulnerabilities)) {
      findings.push({
        tool: "trivy",
        title: cleanText(vuln.Title, vuln.VulnerabilityID || "Trivy vulnerability"),
        severity: normalizeSeverity(vuln.Severity),
        file: target,
        line: 1,
        message: cleanText(vuln.Description || `${vuln.PkgName || "package"} ${vuln.InstalledVersion || ""}`),
        ruleId: vuln.VulnerabilityID || vuln.PkgID || "trivy-vulnerability"
      });
    }

    for (const misconfig of asArray(result.Misconfigurations)) {
      const cause = misconfig.CauseMetadata || {};
      const codeLine = asArray(cause.Code && cause.Code.Lines)[0] || {};
      findings.push({
        tool: "trivy",
        title: cleanText(misconfig.Title, misconfig.ID || "Trivy misconfiguration"),
        severity: normalizeSeverity(misconfig.Severity),
        file: cause.FilePath || target,
        line: firstLine(cause.StartLine || codeLine.Number),
        message: cleanText(misconfig.Message || misconfig.Description),
        ruleId: misconfig.ID || misconfig.AVDID || "trivy-misconfiguration"
      });
    }

    for (const secret of asArray(result.Secrets)) {
      findings.push({
        tool: "trivy",
        title: cleanText(secret.Title, "Trivy secret finding"),
        severity: normalizeSeverity(secret.Severity || "HIGH"),
        file: target,
        line: firstLine(secret.StartLine),
        message: cleanText(secret.RuleID || secret.Category || "Secret-like value detected"),
        ruleId: secret.RuleID || "trivy-secret"
      });
    }
  }

  return findings;
}

module.exports = parse;
