import { AlertTriangle, BadgeCheck, Binary, Bug, Gauge, ListChecks, ShieldAlert, ShieldQuestion } from "lucide-react";

function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

export default function SummaryCards({ summary, findings, scenarios }) {
  const mapped = findings.filter((finding) => finding.mapped).length;
  const unmapped = findings.length - mapped;
  const toolsReporting = new Set(findings.map((finding) => finding.tool)).size;
  const coveredScenarios = new Set(findings.filter((finding) => finding.mapped).map((finding) => finding.scenarioId)).size;
  const totalScenarios = summary?.totalScenarios || scenarios.length || 10;
  const coverage = totalScenarios ? Math.round((coveredScenarios / totalScenarios) * 1000) / 10 : 0;

  const cards = [
    { label: "Total Findings", value: findings.length, icon: Bug, tone: "blue" },
    { label: "Mapped Findings", value: mapped, icon: BadgeCheck, tone: "green" },
    { label: "Unmapped Findings", value: unmapped, icon: ShieldQuestion, tone: "amber" },
    { label: "Critical Findings", value: countSeverity(findings, "CRITICAL"), icon: ShieldAlert, tone: "red" },
    { label: "High Findings", value: countSeverity(findings, "HIGH"), icon: AlertTriangle, tone: "orange" },
    { label: "Tools Reporting", value: toolsReporting, icon: Binary, tone: "blue" },
    { label: "CWE Scenarios", value: totalScenarios, icon: ListChecks, tone: "green" },
    { label: "Combined Coverage", value: `${coverage}%`, icon: Gauge, tone: "amber" }
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
