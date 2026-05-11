import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Circle, CircleSlash, Layers3 } from "lucide-react";

import { countMappedFindings, recommendToolSets, scenarioTools } from "../utils/coverage.js";

function runtimeForTools(diagnostics, tools) {
  return tools.reduce((sum, tool) => {
    const item = diagnostics.find((diagnostic) => diagnostic.tool === tool);
    return sum + (Number(item?.runtimeSeconds) || 0);
  }, 0);
}

function formatRuntime(seconds) {
  if (!seconds) return "n/a";
  return `${Math.round(seconds * 10) / 10}s`;
}

export default function ToolRecommendations({ findings, scenarios, tools, diagnostics }) {
  const scenarioIds = useMemo(() => scenarios.map((scenario) => scenario.id), [scenarios]);
  const [selectedScenarioIds, setSelectedScenarioIds] = useState([]);

  useEffect(() => {
    setSelectedScenarioIds((current) => {
      const available = new Set(scenarioIds);
      const retained = current.filter((scenarioId) => available.has(scenarioId));
      return retained.length ? retained : scenarioIds;
    });
  }, [scenarioIds]);

  const recommendationData = useMemo(
    () => recommendToolSets(findings, scenarios, selectedScenarioIds, tools),
    [findings, scenarios, selectedScenarioIds, tools]
  );

  function toggleScenario(scenarioId) {
    setSelectedScenarioIds((current) => {
      if (current.includes(scenarioId)) {
        return current.filter((id) => id !== scenarioId);
      }
      return [...current, scenarioId];
    });
  }

  if (!scenarios.length) {
    return <p className="empty-inline">No scenarios are available for recommendations.</p>;
  }

  return (
    <div className="recommendation-layout">
      <section className="recommendation-selector">
        <div className="selector-heading">
          <div>
            <h3>Select Vulnerabilities</h3>
            <p>{selectedScenarioIds.length} of {scenarios.length} scenarios selected</p>
          </div>
          <div className="selector-actions">
            <button type="button" onClick={() => setSelectedScenarioIds(scenarioIds)}>All</button>
            <button type="button" onClick={() => setSelectedScenarioIds([])}>Clear</button>
          </div>
        </div>

        <div className="scenario-picker">
          {scenarios.map((scenario) => {
            const selected = selectedScenarioIds.includes(scenario.id);
            const detectingTools = scenarioTools(findings, scenario.id, tools);
            return (
              <button
                type="button"
                key={scenario.id}
                className={selected ? "scenario-choice selected" : "scenario-choice"}
                onClick={() => toggleScenario(scenario.id)}
              >
                {selected ? <CheckCircle2 size={17} /> : <Circle size={17} />}
                <span>
                  <strong>{scenario.id}</strong>
                  <small>{scenario.title}</small>
                  <small>{detectingTools.length} eligible tools detect this scenario</small>
                </span>
              </button>
            );
          })}
        </div>
      </section>

      <section className="recommendation-results">
        <div className="recommendation-summary">
          <div>
            <span>Fewest tools</span>
            <strong>{recommendationData.recommendations[0]?.tools.length || 0}</strong>
          </div>
          <div>
            <span>Coverable selected</span>
            <strong>{recommendationData.coverableScenarioIds.length}</strong>
          </div>
          <div>
            <span>Not detected</span>
            <strong>{recommendationData.unavailableScenarioIds.length}</strong>
          </div>
        </div>

        {recommendationData.unavailableScenarioIds.length ? (
          <div className="recommendation-warning">
            <CircleSlash size={18} />
            <span>Selected scenarios with no mapped finding from eligible tools: {recommendationData.unavailableScenarioIds.join(", ")}</span>
          </div>
        ) : null}

        {!selectedScenarioIds.length ? (
          <p className="empty-inline">Select at least one scenario to calculate recommendations.</p>
        ) : recommendationData.recommendations.length ? (
          <div className="recommendation-list">
            {recommendationData.recommendations.map((recommendation, index) => {
              const runtime = runtimeForTools(diagnostics, recommendation.tools);
              return (
                <article className="recommendation-card" key={recommendation.tools.join("|")}>
                  <div className="recommendation-card-heading">
                    <div>
                      <span className="badge mapped">Recommendation {index + 1}</span>
                      <h3>{recommendation.tools.join(" + ")}</h3>
                    </div>
                    <Layers3 size={22} />
                  </div>

                  <dl className="recommendation-meta">
                    <div>
                      <dt>Scenario coverage</dt>
                      <dd>{recommendation.coveragePercent}%</dd>
                    </div>
                    <div>
                      <dt>CVSS impact coverage</dt>
                      <dd>{recommendation.weightedCoverage.coveragePercent}%</dd>
                    </div>
                    <div>
                      <dt>Mapped findings</dt>
                      <dd>{recommendation.findingsCount}</dd>
                    </div>
                    <div>
                      <dt>Scanner runtime</dt>
                      <dd>{formatRuntime(runtime)}</dd>
                    </div>
                  </dl>

                  <div className="recommendation-covered">
                    {recommendation.coveredScenarioIds.map((scenarioId) => (
                      <span className="badge mapped" key={scenarioId}>{scenarioId}</span>
                    ))}
                  </div>

                  <div className="recommendation-tools">
                    {recommendation.tools.map((tool) => (
                      <div key={tool}>
                        <strong>{tool}</strong>
                        <span>
                          {recommendation.coveredScenarioIds
                            .filter((scenarioId) => countMappedFindings(findings, tool, scenarioId) > 0)
                            .join(", ")}
                        </span>
                      </div>
                    ))}
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          <p className="empty-inline">No eligible tool combination covers the selected mapped scenarios.</p>
        )}
      </section>
    </div>
  );
}
