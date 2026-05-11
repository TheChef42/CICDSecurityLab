import { countMappedFindings } from "../utils/coverage.js";

export default function ToolScenarioMatrix({ findings, scenarios, tools }) {
  if (!scenarios.length) {
    return <div className="empty-inline">No scenario catalog has been generated yet.</div>;
  }

  return (
    <div className="matrix-wrap">
      <table className="matrix-table">
        <thead>
          <tr>
            <th>Scenario</th>
            {tools.map((tool) => (
              <th key={tool}>{tool}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {scenarios.map((scenario) => (
            <tr key={scenario.id}>
              <th>
                <span>{scenario.id}</span>
                <small>{scenario.title}</small>
                <small>CVSS {scenario.cvss?.baseScore ?? "n/a"} {scenario.cvss?.selectedStatistic ? `(${scenario.cvss.selectedStatistic})` : ""} | intended {scenario.intendedVulnerabilityCount || 1}</small>
              </th>
              {tools.map((tool) => {
                const count = countMappedFindings(findings, tool, scenario.id);
                const intended = scenario.intendedVulnerabilityCount || 1;
                return (
                  <td key={`${scenario.id}-${tool}`}>
                    <span className={count > 0 ? "matrix-cell detected" : "matrix-cell missed"}>
                      {count > 0 ? "detected" : "missed"}
                      <strong>{count}/{intended}</strong>
                    </span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
