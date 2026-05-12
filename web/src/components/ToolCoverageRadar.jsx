import { useEffect, useMemo, useState } from "react";
import { combinedCoverage, scenarioCoverageCredit, scenarioImpact, scenarioWeight } from "../utils/coverage.js";

const COLORS = [
  "#6bbcff",
  "#49df92",
  "#f4c34d",
  "#ff9c55",
  "#ff6b73",
  "#9bd3c7",
  "#b8a7ff",
  "#d7e2ef"
];

function polarPoint(index, total, radius, centerX, centerY) {
  const angle = (-Math.PI / 2) + ((Math.PI * 2 * index) / total);
  return {
    x: centerX + Math.cos(angle) * radius,
    y: centerY + Math.sin(angle) * radius
  };
}

function polygonPoints(values, axisCount, radius, centerX, centerY) {
  return values
    .map((value, index) => {
      const point = polarPoint(index, axisCount, radius * (visualPercent(value) / 100), centerX, centerY);
      return `${point.x.toFixed(1)},${point.y.toFixed(1)}`;
    })
    .join(" ");
}

function visualPercent(value) {
  return value <= 0 ? 8 : value;
}

function average(values) {
  if (!values.length) return 0;
  return Math.round((values.reduce((sum, value) => sum + value, 0) / values.length) * 10) / 10;
}

function toolRuntime(diagnostics, tools) {
  const selected = new Set(tools);
  return diagnostics
    .filter((item) => selected.has(item.tool))
    .reduce((sum, item) => sum + (Number(item.durationSeconds) || 0), 0);
}

function strictCombinedCoverage(findings, scenarios, selectedTools) {
  const scenarioCredits = Object.fromEntries(
    scenarios.map((scenario) => [scenario.id, scenarioCoverageCredit(findings, scenario, selectedTools)])
  );
  const totalCredit = Object.values(scenarioCredits).reduce((sum, credit) => sum + credit.fraction, 0);
  const totalWeight = scenarios.reduce((sum, scenario) => sum + scenarioWeight(scenario), 0);
  const coveredWeight = scenarios.reduce((sum, scenario) => {
    return sum + (scenarioWeight(scenario) * scenarioCredits[scenario.id].fraction);
  }, 0);

  return {
    selectedTools,
    scenarioCredits,
    coveragePercent: scenarios.length ? Math.round((totalCredit / scenarios.length) * 1000) / 10 : 0,
    coveredScenarioIds: scenarios
      .filter((scenario) => scenarioCredits[scenario.id].fraction > 0)
      .map((scenario) => scenario.id),
    missedScenarioIds: scenarios
      .filter((scenario) => scenarioCredits[scenario.id].fraction === 0)
      .map((scenario) => scenario.id),
    partiallyCoveredScenarioIds: scenarios
      .filter((scenario) => scenarioCredits[scenario.id].fraction > 0 && scenarioCredits[scenario.id].fraction < 1)
      .map((scenario) => scenario.id),
    weightedCoverage: {
      coveredWeight: Math.round(coveredWeight * 10) / 10,
      totalWeight: Math.round(totalWeight * 10) / 10,
      coveragePercent: totalWeight ? Math.round((coveredWeight / totalWeight) * 1000) / 10 : 0
    }
  };
}

export default function ToolCoverageRadar({ findings, scenarios, tools, diagnostics }) {
  const [comboTools, setComboTools] = useState(tools);
  const [visibleTools, setVisibleTools] = useState(tools);
  const toolKey = tools.join("|");

  useEffect(() => {
    setComboTools(tools);
    setVisibleTools(tools);
  }, [toolKey, tools]);

  const axisCount = scenarios.length;
  const chart = useMemo(() => {
    if (axisCount < 3) return null;

    const combo = strictCombinedCoverage(findings, scenarios, comboTools);
    const axes = scenarios.map((scenario) => {
      const impact = scenarioImpact(scenario);
      return {
        id: scenario.id,
        title: scenario.title,
        intended: scenario.intendedVulnerabilityCount || 1,
        impact,
        comboCredit: scenarioCoverageCredit(findings, scenario, comboTools)
      };
    });

    const profiles = visibleTools.map((tool, index) => {
      const credits = scenarios.map((scenario) => scenarioCoverageCredit(findings, scenario, [tool]));
      const values = credits.map((credit) => credit.percent);
      const runtime = toolRuntime(diagnostics, [tool]);
      return {
        id: tool,
        label: tool,
        type: "tool",
        color: COLORS[index % COLORS.length],
        values,
        averageCoverage: average(values),
        weightedCoverage: combinedCoverage(findings, scenarios, [tool]).weightedCoverage.coveragePercent,
        runtime,
        coveredCount: credits.reduce((sum, credit) => sum + credit.fraction, 0)
      };
    });

    const comboValues = axes.map((axis) => axis.comboCredit.percent);
    profiles.push({
      id: "selected-combo",
      label: `selected combo (${comboTools.length})`,
      type: "combo",
      color: "#ffffff",
      values: comboValues,
      averageCoverage: combo.coveragePercent,
      weightedCoverage: combo.weightedCoverage.coveragePercent,
      runtime: toolRuntime(diagnostics, comboTools),
      coveredCount: combo.coveredScenarioIds.length,
      missedScenarioIds: combo.missedScenarioIds,
      partiallyCoveredScenarioIds: combo.partiallyCoveredScenarioIds
    });

    return { axes, profiles, combo };
  }, [axisCount, comboTools, diagnostics, findings, scenarios, visibleTools]);

  function toggleComboTool(tool) {
    setComboTools((current) => (
      current.includes(tool) ? current.filter((item) => item !== tool) : [...current, tool]
    ));
  }

  function toggleVisibleTool(tool) {
    setVisibleTools((current) => (
      current.includes(tool) ? current.filter((item) => item !== tool) : [...current, tool]
    ));
  }

  if (!scenarios.length) {
    return <div className="empty-inline">No scenario catalog has been generated yet.</div>;
  }

  if (axisCount < 3) {
    return <div className="empty-inline">Select at least three scenarios to render a spider chart.</div>;
  }

  const centerX = 360;
  const centerY = 250;
  const radius = 178;
  const rings = [8, 25, 50, 75, 100];

  return (
    <div className="radar-layout">
      <section className="radar-controls">
        <div>
          <h3>Selected combo</h3>
          <p>Union coverage for the tools checked here is drawn as the white trace.</p>
          <p>Zero coverage is drawn on the inner baseline so missed scenarios stay visible; the percentage math is unchanged.</p>
          <div className="radar-picker">
            {tools.map((tool) => (
              <label className="check-option" key={`combo-${tool}`}>
                <input
                  type="checkbox"
                  checked={comboTools.includes(tool)}
                  onChange={() => toggleComboTool(tool)}
                />
                <span>{tool}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <h3>Individual traces</h3>
          <p>Toggle which single-tool traces are shown against the combo.</p>
          <div className="radar-picker">
            {tools.map((tool) => (
              <label className="check-option" key={`visible-${tool}`}>
                <input
                  type="checkbox"
                  checked={visibleTools.includes(tool)}
                  onChange={() => toggleVisibleTool(tool)}
                />
                <span>{tool}</span>
              </label>
            ))}
          </div>
        </div>
      </section>

      <section className="radar-stage">
        <svg className="radar-chart" viewBox="0 0 720 540" role="img" aria-label="Tool coverage spider chart">
          {rings.map((ring) => (
            <polygon
              key={ring}
              className={ring === 8 ? "radar-ring zero" : "radar-ring"}
              points={Array.from({ length: axisCount }, (_, index) => {
                const point = polarPoint(index, axisCount, radius * (ring / 100), centerX, centerY);
                return `${point.x.toFixed(1)},${point.y.toFixed(1)}`;
              }).join(" ")}
            />
          ))}
          {chart.axes.map((axis, index) => {
            const edge = polarPoint(index, axisCount, radius, centerX, centerY);
            const label = polarPoint(index, axisCount, radius + 54, centerX, centerY);
            return (
              <g key={axis.id}>
                <line className="radar-axis" x1={centerX} y1={centerY} x2={edge.x} y2={edge.y} />
                <text className="radar-label" x={label.x} y={label.y}>
                  <tspan x={label.x} dy="0">{axis.id}</tspan>
                  <tspan x={label.x} dy="14">{axis.comboCredit.credited}/{axis.comboCredit.intended}</tspan>
                </text>
              </g>
            );
          })}
          {chart.profiles.map((profile) => (
            <g key={profile.id}>
              <polygon
                className={profile.type === "combo" ? "radar-area combo" : "radar-area"}
                points={polygonPoints(profile.values, axisCount, radius, centerX, centerY)}
                style={{ "--radar-color": profile.color }}
              />
              <polyline
                className={profile.type === "combo" ? "radar-line combo" : "radar-line"}
                points={`${polygonPoints(profile.values, axisCount, radius, centerX, centerY)} ${polygonPoints(profile.values, axisCount, radius, centerX, centerY).split(" ")[0]}`}
                style={{ "--radar-color": profile.color }}
              />
              {profile.values.map((value, index) => {
                const point = polarPoint(index, axisCount, radius * (visualPercent(value) / 100), centerX, centerY);
                return (
                  <circle
                    key={`${profile.id}-${index}`}
                    className={value <= 0 ? "radar-point zero" : "radar-point"}
                    cx={point.x}
                    cy={point.y}
                    r={profile.type === "combo" ? 3.6 : 2.4}
                    style={{ "--radar-color": profile.color }}
                  />
                );
              })}
            </g>
          ))}
          <text className="radar-center-label" x={centerX} y={centerY - 6}>coverage</text>
          <text className="radar-center-value" x={centerX} y={centerY + 20}>{chart.combo.coveragePercent}%</text>
        </svg>
      </section>

      <section className="radar-legend">
        {chart.profiles.map((profile) => (
          <article className={profile.type === "combo" ? "radar-profile combo" : "radar-profile"} key={profile.id}>
            <span className="radar-swatch" style={{ background: profile.color }} />
            <div>
              <h3>{profile.label}</h3>
              <p>
                {profile.averageCoverage}% scenario coverage, {profile.weightedCoverage}% CVSS-weighted coverage
                {profile.runtime ? `, ${Math.round(profile.runtime * 10) / 10}s runtime` : ""}
              </p>
              {profile.type === "combo" ? (
                <p>
                  Missed: {profile.missedScenarioIds.join(", ") || "none"}.
                  Partial: {profile.partiallyCoveredScenarioIds.join(", ") || "none"}.
                </p>
              ) : null}
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
