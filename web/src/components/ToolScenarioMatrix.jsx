import { detectionStats, scenarioImpact } from "../utils/coverage.js";

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
                {(() => {
                  const impact = scenarioImpact(scenario);
                  return (
                    <>
                      <small>
                        CVSS {impact.score || "n/a"} {scenario.cvss?.selectedStatistic ? `(${scenario.cvss.selectedStatistic})` : ""} | intended {scenario.intendedVulnerabilityCount || 1}
                      </small>
                      <small>
                        <span className={`impact-text ${impact.level.toLowerCase()}`}>{impact.level}</span> impact
                      </small>
                    </>
                  );
                })()}
              </th>
              {tools.map((tool) => {
                const stats = detectionStats(findings, tool, scenario);
                return (
                  <td key={`${scenario.id}-${tool}`}>
                    <span className={stats.detected ? "matrix-cell detected" : "matrix-cell missed"}>
                      <span>{stats.detected ? "detected" : "missed"}</span>
                      <strong>{stats.creditedCount}/{stats.intendedCount}</strong>
                      {stats.rawCount > 0 ? (
                        <em>
                          {stats.rawCount} raw{stats.extraCount ? `, ${stats.extraCount} extra` : ""}
                        </em>
                      ) : null}
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
