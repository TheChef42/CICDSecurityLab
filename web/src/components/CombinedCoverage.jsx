import { useEffect, useMemo, useState } from "react";
import { combinedCoverage } from "../utils/coverage.js";

export default function CombinedCoverage({ findings, scenarios, tools }) {
  const [selectedTools, setSelectedTools] = useState(tools);
  const toolKey = tools.join("|");

  useEffect(() => {
    setSelectedTools(tools);
  }, [toolKey, tools]);

  const coverage = useMemo(
    () => combinedCoverage(findings, scenarios, selectedTools),
    [findings, scenarios, selectedTools]
  );

  function toggleTool(tool) {
    setSelectedTools((current) => {
      if (current.includes(tool)) return current.filter((item) => item !== tool);
      return [...current, tool];
    });
  }

  return (
    <div className="coverage-layout">
      <div className="tool-picker">
        {tools.map((tool) => (
          <label key={tool} className="check-option">
            <input
              type="checkbox"
              checked={selectedTools.includes(tool)}
              onChange={() => toggleTool(tool)}
            />
            <span>{tool}</span>
          </label>
        ))}
      </div>

      <div className="coverage-meter">
        <span>{coverage.coveragePercent}%</span>
        <div className="meter-track">
          <div className="meter-fill" style={{ width: `${coverage.coveragePercent}%` }} />
        </div>
        <p>{coverage.coveredScenarioIds.length} of {scenarios.length || 10} scenarios covered by selected tools</p>
      </div>

      <div className="coverage-columns">
        <section>
          <h3>Selected tools</h3>
          <p>{coverage.selectedTools.join(", ") || "none"}</p>
        </section>
        <section>
          <h3>Covered scenario IDs</h3>
          <p>{coverage.coveredScenarioIds.join(", ") || "none"}</p>
        </section>
        <section>
          <h3>Missed scenario IDs</h3>
          <p>{coverage.missedScenarioIds.join(", ") || "none"}</p>
        </section>
        <section>
          <h3>Detected by only one selected tool</h3>
          <p>
            {coverage.singleToolDetections.length
              ? coverage.singleToolDetections.map((item) => `${item.scenarioId} (${item.tool})`).join(", ")
              : "none"}
          </p>
        </section>
      </div>

      <div className="overlap-grid">
        {coverage.overlap.map((item) => (
          <article className="overlap-card" key={item.pair}>
            <strong>{item.pair}</strong>
            <span>{item.sharedScenarioIds.length} shared</span>
            <p>{item.sharedScenarioIds.join(", ") || "none"}</p>
          </article>
        ))}
      </div>
    </div>
  );
}
