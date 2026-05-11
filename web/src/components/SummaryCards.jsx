import { AlertTriangle, BadgeCheck, Binary, Bug, Gauge, ListChecks, ShieldAlert, ShieldQuestion, Target } from "lucide-react";
import { impactLevelFromScore, uniqueCoveredScenarioIds } from "../utils/coverage.js";

function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

export default function SummaryCards({ findings, scenarios }) {
  const mapped = findings.filter((finding) => finding.mapped).length;
  const unmapped = findings.length - mapped;
  const toolsReporting = new Set(findings.map((finding) => finding.tool)).size;
  const coveredScenarioIds = uniqueCoveredScenarioIds(findings);
  const coveredScenarioSet = new Set(coveredScenarioIds);
  const coveredScenarios = coveredScenarioIds.length;
  const totalScenarios = scenarios.length;
  const coverage = totalScenarios ? Math.round((coveredScenarios / totalScenarios) * 1000) / 10 : 0;
  const totalWeight = scenarios.reduce((sum, scenario) => sum + (Number(scenario.cvss?.baseScore) || 0), 0);
  const coveredWeight = coveredScenarioIds.reduce((sum, scenarioId) => {
    const scenario = scenarios.find((item) => item.id === scenarioId);
    return sum + (Number(scenario?.cvss?.baseScore) || 0);
  }, 0);
  const weightedCoverage = totalWeight ? Math.round((coveredWeight / totalWeight) * 1000) / 10 : 0;
  const intendedVulnerabilities = scenarios.reduce((sum, scenario) => sum + (Number(scenario.intendedVulnerabilityCount) || 1), 0);
  const extraScenarioFindings = findings.filter((finding) => finding.coverageExtra).length;
  const highImpactScenarios = scenarios.filter((scenario) => {
    const level = impactLevelFromScore(scenario.cvss?.baseScore);
    return level === "HIGH" || level === "CRITICAL";
  });
  const highImpactCovered = highImpactScenarios.filter((scenario) => coveredScenarioSet.has(scenario.id)).length;

  const cards = [
    { label: "Total Findings", value: findings.length, icon: Bug, tone: "blue" },
    { label: "Mapped Findings", value: mapped, icon: BadgeCheck, tone: "green" },
    { label: "Unmapped Findings", value: unmapped, icon: ShieldQuestion, tone: "amber" },
    { label: "Critical Findings", value: countSeverity(findings, "CRITICAL"), icon: ShieldAlert, tone: "red" },
    { label: "High Findings", value: countSeverity(findings, "HIGH"), icon: AlertTriangle, tone: "orange" },
    { label: "Tools Reporting", value: toolsReporting, icon: Binary, tone: "blue" },
    { label: "CWE Scenarios", value: totalScenarios, icon: ListChecks, tone: "green" },
    { label: "Intended Vulns", value: intendedVulnerabilities, icon: Target, tone: "green" },
    { label: "Extra Raw Findings", value: extraScenarioFindings, icon: ShieldQuestion, tone: "amber" },
    { label: "Scenario Coverage", value: `${coverage}%`, icon: Gauge, tone: "amber" },
    { label: "CVSS Impact Coverage", value: `${weightedCoverage}%`, icon: ShieldAlert, tone: "red" },
    { label: "High Impact Covered", value: `${highImpactCovered}/${highImpactScenarios.length}`, icon: AlertTriangle, tone: "orange" }
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
