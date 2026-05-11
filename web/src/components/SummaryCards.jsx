import { AlertTriangle, BadgeCheck, Binary, Bug, Gauge, ListChecks, ShieldAlert, ShieldQuestion, Target } from "lucide-react";

function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

export default function SummaryCards({ findings, scenarios }) {
  const mapped = findings.filter((finding) => finding.mapped).length;
  const unmapped = findings.length - mapped;
  const toolsReporting = new Set(findings.map((finding) => finding.tool)).size;
  const coveredScenarios = new Set(findings.filter((finding) => finding.mapped).map((finding) => finding.scenarioId)).size;
  const totalScenarios = scenarios.length;
  const coverage = totalScenarios ? Math.round((coveredScenarios / totalScenarios) * 1000) / 10 : 0;
  const totalWeight = scenarios.reduce((sum, scenario) => sum + (Number(scenario.cvss?.baseScore) || 0), 0);
  const coveredWeight = Array.from(new Set(findings.filter((finding) => finding.mapped).map((finding) => finding.scenarioId)))
    .reduce((sum, scenarioId) => {
      const scenario = scenarios.find((item) => item.id === scenarioId);
      return sum + (Number(scenario?.cvss?.baseScore) || 0);
    }, 0);
  const weightedCoverage = totalWeight ? Math.round((coveredWeight / totalWeight) * 1000) / 10 : 0;
  const intendedVulnerabilities = scenarios.reduce((sum, scenario) => sum + (Number(scenario.intendedVulnerabilityCount) || 1), 0);
  const duplicateFindings = findings.filter((finding) => finding.duplicate).length;

  const cards = [
    { label: "Total Findings", value: findings.length, icon: Bug, tone: "blue" },
    { label: "Mapped Findings", value: mapped, icon: BadgeCheck, tone: "green" },
    { label: "Unmapped Findings", value: unmapped, icon: ShieldQuestion, tone: "amber" },
    { label: "Critical Findings", value: countSeverity(findings, "CRITICAL"), icon: ShieldAlert, tone: "red" },
    { label: "High Findings", value: countSeverity(findings, "HIGH"), icon: AlertTriangle, tone: "orange" },
    { label: "Tools Reporting", value: toolsReporting, icon: Binary, tone: "blue" },
    { label: "CWE Scenarios", value: totalScenarios, icon: ListChecks, tone: "green" },
    { label: "Intended Vulns", value: intendedVulnerabilities, icon: Target, tone: "green" },
    { label: "Duplicate Findings", value: duplicateFindings, icon: ShieldQuestion, tone: "amber" },
    { label: "Combined Coverage", value: `${coverage}%`, icon: Gauge, tone: "amber" },
    { label: "CVSS Weighted Coverage", value: `${weightedCoverage}%`, icon: ShieldAlert, tone: "red" }
  ];

  return (
    <section className="summary-grid" aria-label="Summary metrics">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <article className={`summary-card ${card.tone}`} key={card.label}>
            <div className="summary-icon">
              <Icon size={19} />
            </div>
            <div>
              <p>{card.label}</p>
              <strong>{card.value}</strong>
            </div>
          </article>
        );
      })}
    </section>
  );
}
