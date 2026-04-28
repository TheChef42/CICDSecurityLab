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

const mappedOptions = [
  { value: "mapped", label: "Mapped" },
  { value: "unmapped", label: "Unmapped" }
];

function MultiSelectFilter({ label, options, selected, onChange }) {
  const selectedSet = new Set(selected);
  const summary = selected.length === 0
    ? `All ${label.toLowerCase()}`
    : selected.length === 1
      ? options.find((option) => option.value === selected[0])?.label || selected[0]
      : `${selected.length} selected`;

  function toggle(value) {
    if (selectedSet.has(value)) {
      onChange(selected.filter((item) => item !== value));
      return;
    }
    onChange([...selected, value]);
  }

  return (
    <details className="multi-select">
      <summary>
        <span>{summary}</span>
      </summary>
      <div className="multi-select-menu">
        <button type="button" className="clear-filter" onClick={() => onChange([])}>
          All {label.toLowerCase()}
        </button>
        {options.map((option) => (
          <label key={option.value} className="multi-option">
            <input
              type="checkbox"
              checked={selectedSet.has(option.value)}
              onChange={() => toggle(option.value)}
            />
            <span>{option.label}</span>
          </label>
        ))}
      </div>
    </details>
  );
}

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
    () => (filters.tool.length ? TOOLS.filter((tool) => filters.tool.includes(tool)) : TOOLS),
    [filters.tool]
  );
  const filteredScenarios = useMemo(
    () => scenarios.filter((scenario) => {
      if (filters.scenarioId.length && !filters.scenarioId.includes(scenario.id)) return false;
      if (filters.cwe.length && !filters.cwe.includes(scenario.cwe)) return false;
      if (filters.owaspCategory.length && !filters.owaspCategory.includes(scenario.owaspCategory)) return false;
      return true;
    }),
    [filters.cwe, filters.owaspCategory, filters.scenarioId, scenarios]
  );
  const filteredDiagnostics = useMemo(
    () => (filters.tool.length ? diagnostics.filter((item) => filters.tool.includes(item.tool)) : diagnostics),
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
        <MultiSelectFilter
          label="Tools"
          options={options.tools.map((tool) => ({ value: tool, label: tool }))}
          selected={filters.tool}
          onChange={(tool) => setFilters({ ...filters, tool })}
        />
        <MultiSelectFilter
          label="Severities"
          options={options.severities.map((severity) => ({ value: severity, label: severity }))}
          selected={filters.severity}
          onChange={(severity) => setFilters({ ...filters, severity })}
        />
        <MultiSelectFilter
          label="OWASP categories"
          options={options.owaspCategories.map((category) => ({ value: category, label: category }))}
          selected={filters.owaspCategory}
          onChange={(owaspCategory) => setFilters({ ...filters, owaspCategory })}
        />
        <MultiSelectFilter
          label="CWEs"
          options={options.cwes.map((cwe) => ({ value: cwe, label: cwe }))}
          selected={filters.cwe}
          onChange={(cwe) => setFilters({ ...filters, cwe })}
        />
        <MultiSelectFilter
          label="Scenarios"
          options={options.scenarios.map((scenarioId) => ({ value: scenarioId, label: scenarioId }))}
          selected={filters.scenarioId}
          onChange={(scenarioId) => setFilters({ ...filters, scenarioId })}
        />
        <MultiSelectFilter
          label="Mapping states"
          options={mappedOptions}
          selected={filters.mapped}
          onChange={(mapped) => setFilters({ ...filters, mapped })}
        />
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
