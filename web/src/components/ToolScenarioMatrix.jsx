import { useState } from "react";
import { Download } from "lucide-react";
import { detectionStats, scenarioImpact } from "../utils/coverage.js";

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function wrapText(context, text, x, y, maxWidth, lineHeight, maxLines = 3) {
  const words = String(text || "").split(/\s+/);
  const lines = [];
  let line = "";

  for (const word of words) {
    const testLine = line ? `${line} ${word}` : word;
    if (context.measureText(testLine).width > maxWidth && line) {
      lines.push(line);
      line = word;
      if (lines.length === maxLines - 1) break;
    } else {
      line = testLine;
    }
  }

  if (line) lines.push(line);
  lines.slice(0, maxLines).forEach((item, index) => {
    context.fillText(index === maxLines - 1 && words.join(" ").length > item.length ? `${item}...` : item, x, y + index * lineHeight);
  });
  return lines.length * lineHeight;
}

function roundedRect(context, x, y, width, height, radius) {
  context.beginPath();
  context.moveTo(x + radius, y);
  context.arcTo(x + width, y, x + width, y + height, radius);
  context.arcTo(x + width, y + height, x, y + height, radius);
  context.arcTo(x, y + height, x, y, radius);
  context.arcTo(x, y, x + width, y, radius);
  context.closePath();
}

async function exportMatrixAsPng({ findings, scenarios, tools, filename }) {
  const darkMode = document.documentElement.dataset.theme !== "light";
  const palette = darkMode
    ? {
        background: "#0c111a",
        panel: "#101722",
        border: "#243044",
        title: "#edf2f7",
        muted: "#8fa0b8",
        accent: "#8fd4ff",
        detectedBg: "#143327",
        detectedBorder: "#236f4e",
        detectedText: "#65eea8",
        missedBg: "#1b2330",
        missedBorder: "#303b4f",
        missedText: "#aebbd0",
        high: "#ffad76",
        medium: "#f5d36d",
        critical: "#ff8a91",
        low: "#8fd4ff"
      }
    : {
        background: "#ffffff",
        panel: "#f8fafc",
        border: "#dbe3ef",
        title: "#0f172a",
        muted: "#64748b",
        accent: "#0369a1",
        detectedBg: "#dcfce7",
        detectedBorder: "#86efac",
        detectedText: "#047857",
        missedBg: "#f1f5f9",
        missedBorder: "#cbd6e5",
        missedText: "#64748b",
        high: "#c2410c",
        medium: "#854d0e",
        critical: "#b91c1c",
        low: "#075985"
      };

  const scenarioWidth = 270;
  const toolWidth = 142;
  const headerHeight = 76;
  const rowHeight = 96;
  const padding = 28;
  const width = padding * 2 + scenarioWidth + tools.length * toolWidth;
  const height = padding * 2 + headerHeight + scenarios.length * rowHeight;
  const scale = Math.min(window.devicePixelRatio || 1, 2);
  const canvas = document.createElement("canvas");
  canvas.width = width * scale;
  canvas.height = height * scale;
  const context = canvas.getContext("2d");
  context.scale(scale, scale);
  context.fillStyle = palette.background;
  context.fillRect(0, 0, width, height);

  context.fillStyle = palette.title;
  context.font = "700 18px Inter, Arial, sans-serif";
  context.fillText("Tool x Scenario Matrix", padding, 24);
  context.fillStyle = palette.muted;
  context.font = "12px Inter, Arial, sans-serif";
  context.fillText(`Filtered export: ${scenarios.length} scenarios, ${tools.length} tools`, padding, 44);

  const tableX = padding;
  const tableY = padding + 34;
  context.fillStyle = palette.panel;
  roundedRect(context, tableX - 10, tableY - 10, width - padding * 2 + 20, height - tableY - padding + 20, 8);
  context.fill();

  context.fillStyle = palette.accent;
  context.font = "700 11px Inter, Arial, sans-serif";
  context.fillText("SCENARIO", tableX, tableY + 28);
  tools.forEach((tool, index) => {
    context.fillText(tool.toUpperCase(), tableX + scenarioWidth + index * toolWidth, tableY + 28);
  });

  scenarios.forEach((scenario, rowIndex) => {
    const rowY = tableY + headerHeight + rowIndex * rowHeight;
    context.strokeStyle = palette.border;
    context.beginPath();
    context.moveTo(tableX, rowY - 14);
    context.lineTo(width - padding, rowY - 14);
    context.stroke();

    const impact = scenarioImpact(scenario);
    context.fillStyle = palette.title;
    context.font = "700 14px Inter, Arial, sans-serif";
    context.fillText(scenario.id, tableX, rowY + 8);
    context.fillStyle = palette.muted;
    context.font = "11px Inter, Arial, sans-serif";
    wrapText(context, scenario.title, tableX, rowY + 24, scenarioWidth - 18, 13, 2);
    context.fillText(`CVSS ${impact.score || "n/a"} | intended ${scenario.intendedVulnerabilityCount || 1}`, tableX, rowY + 58);
    context.fillStyle = palette[impact.level.toLowerCase()] || palette.muted;
    context.fillText(`${impact.level} impact`, tableX, rowY + 74);

    tools.forEach((tool, colIndex) => {
      const stats = detectionStats(findings, tool, scenario);
      const cellX = tableX + scenarioWidth + colIndex * toolWidth;
      const cellY = rowY + 8;
      const cellWidth = toolWidth - 18;
      const cellHeight = 52;
      context.fillStyle = stats.detected ? palette.detectedBg : palette.missedBg;
      context.strokeStyle = stats.detected ? palette.detectedBorder : palette.missedBorder;
      roundedRect(context, cellX, cellY, cellWidth, cellHeight, 7);
      context.fill();
      context.stroke();

      context.fillStyle = stats.detected ? palette.detectedText : palette.missedText;
      context.font = "13px Inter, Arial, sans-serif";
      context.fillText(stats.detected ? "detected" : "missed", cellX + 10, cellY + 21);
      context.font = "700 13px Inter, Arial, sans-serif";
      context.textAlign = "right";
      context.fillText(`${stats.creditedCount}/${stats.intendedCount}`, cellX + cellWidth - 10, cellY + 21);
      context.textAlign = "left";
      if (stats.rawCount > 0) {
        context.fillStyle = palette.muted;
        context.font = "10px Inter, Arial, sans-serif";
        context.fillText(`${stats.rawCount} raw${stats.extraCount ? `, ${stats.extraCount} extra` : ""}`, cellX + 10, cellY + 39);
      }
    });
  });

  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
  if (!blob) throw new Error("PNG export failed.");
  downloadBlob(blob, filename);
}

export default function ToolScenarioMatrix({ findings, scenarios, tools }) {
  const [exporting, setExporting] = useState(false);

  if (!scenarios.length) {
    return <div className="empty-inline">No scenario catalog has been generated yet.</div>;
  }

  async function handleExport() {
    if (exporting) return;
    setExporting(true);
    try {
      await exportMatrixAsPng({
        findings,
        scenarios,
        tools,
        filename: `tool-scenario-matrix-${new Date().toISOString().slice(0, 10)}.png`
      });
    } catch (error) {
      console.error(error);
      window.alert("The matrix PNG export failed. Please try again.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <div className="matrix-actions">
        <button type="button" className="export-button" onClick={handleExport} disabled={exporting}>
          <Download size={17} />
          <span>{exporting ? "Exporting..." : "Export PNG"}</span>
        </button>
      </div>
      <div className="matrix-wrap">
        <div className="matrix-export-target">
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
                          {stats.nonCreditedMappedCount > 0 ? (
                            <em>{stats.nonCreditedMappedCount} mapped but not coverage evidence</em>
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
      </div>
    </>
  );
}
