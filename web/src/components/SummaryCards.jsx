import { AlertTriangle, BadgeCheck, Binary, Bug, Gauge, ListChecks, ShieldAlert, ShieldQuestion, Target } from "lucide-react";
import { combinedCoverage, impactLevelFromScore, isCoverageEligible } from "../utils/coverage.js";

function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

export default function SummaryCards({ findings, scenarios }) {
  const mapped = findings.filter((finding) => finding.mapped).length;
  const unmapped = findings.length - mapped;
  const toolsReporting = new Set(findings.map((finding) => finding.tool)).size;
  const coverage = combinedCoverage(findings, scenarios, []);
  const coveredScenarioIds = coverage.coveredScenarioIds;
  const coveredScenarioSet = new Set(coveredScenarioIds);
  const totalScenarios = scenarios.length;
  const intendedVulnerabilities = scenarios.reduce((sum, scenario) => sum + (Number(scenario.intendedVulnerabilityCount) || 1), 0);
  const extraScenarioFindings = findings.filter((finding) => finding.coverageExtra).length;
  const nonCoverageMapped = findings.filter((finding) => finding.mapped && !isCoverageEligible(finding)).length;
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
    { label: "Mapped Non-Coverage", value: nonCoverageMapped, icon: ShieldQuestion, tone: "amber" },
    { label: "Scenario Coverage", value: `${coverage.coveragePercent}%`, icon: Gauge, tone: "amber" },
    { label: "CVSS Impact Coverage", value: `${coverage.weightedCoverage.coveragePercent}%`, icon: ShieldAlert, tone: "red" },
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
