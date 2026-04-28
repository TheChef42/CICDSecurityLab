import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Columns3,
  Gauge,
  ListFilter,
  Radar,
  ScrollText,
  ShieldCheck,
  TriangleAlert
} from "lucide-react";

import SummaryCards from "./components/SummaryCards.jsx";
import RawFindings from "./components/RawFindings.jsx";
import ToolScenarioMatrix from "./components/ToolScenarioMatrix.jsx";
import ScenarioCatalog from "./components/ScenarioCatalog.jsx";
import CombinedCoverage from "./components/CombinedCoverage.jsx";
import ToolDiagnostics from "./components/ToolDiagnostics.jsx";
import { TOOLS, SEVERITIES } from "./utils/coverage.js";
import { EMPTY_FILTERS, applyFilters, uniqueValues } from "./utils/filters.js";

const tabs = [
  { id: "findings", label: "Raw Findings", icon: ScrollText },
  { id: "matrix", label: "Tool × Scenario Matrix", icon: Columns3 },
  { id: "catalog", label: "CWE Scenario Catalog", icon: ShieldCheck },
  { id: "coverage", label: "Combined Coverage", icon: Radar },
  { id: "diagnostics", label: "Tool Diagnostics", icon: Activity }
];

async function fetchJson(path, fallback) {
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) return fallback;
    return await response.json();
  } catch {
    return fallback;
  }
}

export default function App() {
  const [findings, setFindings] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [summary, setSummary] = useState(null);
  const [diagnostics, setDiagnostics] = useState([]);
  const [activeTab, setActiveTab] = useState("findings");
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    async function load() {
      const [findingData, scenarioData, summaryData, diagnosticData] = await Promise.all([
        fetchJson("/results/normalized/findings.json", []),
        fetchJson("/results/normalized/scenarios.json", []),
        fetchJson("/results/summary.json", null),
        fetchJson("/results/diagnostics.json", [])
      ]);

      if (mounted) {
        setFindings(Array.isArray(findingData) ? findingData : []);
        setScenarios(Array.isArray(scenarioData) ? scenarioData : []);
        setSummary(summaryData);
        setDiagnostics(Array.isArray(diagnosticData) ? diagnosticData : []);
        setLoading(false);
      }
    }

    load();
    const refresh = window.setInterval(load, 15000);
    return () => {
      mounted = false;
      window.clearInterval(refresh);
    };
  }, []);

  const filteredFindings = useMemo(() => applyFilters(findings, filters), [findings, filters]);
  const filteredTools = useMemo(
    () => (filters.tool === "all" ? TOOLS : TOOLS.filter((tool) => tool === filters.tool)),
    [filters.tool]
  );
  const filteredScenarioIds = useMemo(() => {
    const hasFindingScopedFilter =
      filters.tool !== "all" ||
      filters.severity !== "all" ||
      filters.mapped !== "all";
    const detectedScenarioIds = new Set(filteredFindings.filter((finding) => finding.mapped).map((finding) => finding.scenarioId));

    return new Set(
      scenarios
        .filter((scenario) => {
          if (filters.scenarioId !== "all" && scenario.id !== filters.scenarioId) return false;
          if (filters.cwe !== "all" && scenario.cwe !== filters.cwe) return false;
          if (filters.owaspCategory !== "all" && scenario.owaspCategory !== filters.owaspCategory) return false;
          if (filters.mapped === "unmapped") return false;
          if (hasFindingScopedFilter && !detectedScenarioIds.has(scenario.id)) return false;
          return true;
        })
        .map((scenario) => scenario.id)
    );
  }, [filteredFindings, filters, scenarios]);
  const filteredScenarios = useMemo(
    () => scenarios.filter((scenario) => filteredScenarioIds.has(scenario.id)),
    [filteredScenarioIds, scenarios]
  );
  const filteredDiagnostics = useMemo(
    () => (filters.tool === "all" ? diagnostics : diagnostics.filter((item) => item.tool === filters.tool)),
    [diagnostics, filters.tool]
  );

  const options = useMemo(
    () => ({
      tools: TOOLS,
      severities: SEVERITIES,
      owaspCategories: uniqueValues(findings, "owaspCategory"),
      cwes: uniqueValues(findings, "cwe"),
      scenarios: uniqueValues(findings, "scenarioId")
    }),
    [findings]
  );

  const scanCompleted = Boolean(summary?.scanCompleted) || findings.length > 0 || diagnostics.some((item) => item.status);
  const hasNoResults = !loading && !scanCompleted;
  const ActiveIcon = tabs.find((tab) => tab.id === activeTab)?.icon || Gauge;

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">CI/CD Security Lab</p>
          <h1>Supply Chain Scan Coverage</h1>
        </div>
        <div className="header-status">
          <Gauge size={18} />
          <span>{summary?.generatedAt ? new Date(summary.generatedAt).toLocaleString() : "No scan summary"}</span>
        </div>
      </header>

      <SummaryCards findings={filteredFindings} scenarios={filteredScenarios} />

      <section className="toolbar" aria-label="Finding filters">
        <div className="toolbar-title">
          <ListFilter size={18} />
          <span>Filters</span>
        </div>
        <select value={filters.tool} onChange={(event) => setFilters({ ...filters, tool: event.target.value })}>
          <option value="all">All tools</option>
          {options.tools.map((tool) => (
            <option key={tool} value={tool}>{tool}</option>
          ))}
        </select>
        <select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}>
          <option value="all">All severities</option>
          {options.severities.map((severity) => (
            <option key={severity} value={severity}>{severity}</option>
          ))}
        </select>
        <select value={filters.owaspCategory} onChange={(event) => setFilters({ ...filters, owaspCategory: event.target.value })}>
          <option value="all">All OWASP categories</option>
          {options.owaspCategories.map((category) => (
            <option key={category} value={category}>{category}</option>
          ))}
        </select>
        <select value={filters.cwe} onChange={(event) => setFilters({ ...filters, cwe: event.target.value })}>
          <option value="all">All CWEs</option>
          {options.cwes.map((cwe) => (
            <option key={cwe} value={cwe}>{cwe}</option>
          ))}
        </select>
        <select value={filters.scenarioId} onChange={(event) => setFilters({ ...filters, scenarioId: event.target.value })}>
          <option value="all">All scenarios</option>
          {options.scenarios.map((scenarioId) => (
            <option key={scenarioId} value={scenarioId}>{scenarioId}</option>
          ))}
        </select>
        <select value={filters.mapped} onChange={(event) => setFilters({ ...filters, mapped: event.target.value })}>
          <option value="all">Mapped and unmapped</option>
          <option value="mapped">Mapped only</option>
          <option value="unmapped">Unmapped only</option>
        </select>
      </section>

      <nav className="tabs" aria-label="Dashboard tabs">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              type="button"
              key={tab.id}
              className={activeTab === tab.id ? "tab active" : "tab"}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={17} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {hasNoResults ? (
        <section className="empty-state">
          <TriangleAlert size={24} />
          <div>
            <h2>No scan results yet</h2>
            <p>Run the scanner service to generate normalized findings, summary metrics, and diagnostics.</p>
          </div>
        </section>
      ) : (
        <section className="tab-panel">
          <div className="panel-heading">
            <ActiveIcon size={18} />
            <span>{tabs.find((tab) => tab.id === activeTab)?.label}</span>
          </div>
          {activeTab === "findings" && <RawFindings findings={filteredFindings} />}
          {activeTab === "matrix" && <ToolScenarioMatrix findings={filteredFindings} scenarios={filteredScenarios} tools={filteredTools} />}
          {activeTab === "catalog" && <ScenarioCatalog scenarios={filteredScenarios} />}
          {activeTab === "coverage" && <CombinedCoverage findings={filteredFindings} scenarios={filteredScenarios} tools={filteredTools} />}
          {activeTab === "diagnostics" && <ToolDiagnostics diagnostics={filteredDiagnostics} />}
        </section>
      )}
    </main>
  );
}
