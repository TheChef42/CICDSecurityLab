export default function ScenarioCatalog({ scenarios }) {
  if (!scenarios.length) {
    return <div className="empty-inline">No scenarios are available yet.</div>;
  }

  const totalCvssWeight = scenarios.reduce((sum, scenario) => {
    const score = Number(scenario.cvss?.baseScore);
    return sum + (Number.isFinite(score) && score > 0 ? score : 0);
  }, 0);

  function cvssWeightShare(scenario) {
    const score = Number(scenario.cvss?.baseScore);
    if (!totalCvssWeight || !Number.isFinite(score) || score <= 0) return "n/a";
    return `${Math.round((score / totalCvssWeight) * 1000) / 10}%`;
  }

  return (
    <div className="catalog-grid">
      {scenarios.map((scenario) => (
        <article className="scenario-card" key={scenario.id}>
          <div className="scenario-heading">
            <span className="badge mapped">{scenario.id}</span>
            <span>{scenario.cwe}</span>
          </div>
          <h3>{scenario.title}</h3>
          <p>{scenario.description}</p>
          <dl className="scenario-meta">
            <div>
              <dt>Mapping</dt>
              <dd>
                {scenario.mappingStatus || "n/a"}
                {typeof scenario.nvdCveCount === "number" ? `, ${scenario.nvdCveCount.toLocaleString()} NVD CVEs` : ""}
                {scenario.cweTransition ? `, ${scenario.cweTransition}` : ""}
              </dd>
            </div>
            <div>
              <dt>Representative CVSS</dt>
              <dd>
                {typeof scenario.cvss?.baseScore === "number"
                  ? `${scenario.cvss.baseScore} ${scenario.cvss.severity} (${scenario.cvss.selectedStatistic || "selected"})`
                  : "n/a"}
              </dd>
            </div>
            <div>
              <dt>CVSS weight share</dt>
              <dd>{cvssWeightShare(scenario)} of weighted coverage denominator</dd>
            </div>
            <div>
              <dt>CVSS statistics</dt>
              <dd>
                {typeof scenario.cvss?.scoreMedian === "number"
                  ? `mean ${scenario.cvss.scoreMean}, median ${scenario.cvss.scoreMedian}, p75 ${scenario.cvss.scoreP75}`
                  : "n/a"}
              </dd>
            </div>
            <div>
              <dt>Intended vulnerabilities</dt>
              <dd>
                {scenario.intendedVulnerabilityCount || 1}
                {scenario.intendedVulnerabilityNotes ? ` - ${scenario.intendedVulnerabilityNotes}` : ""}
              </dd>
            </div>
            <div>
              <dt>OWASP</dt>
              <dd>{scenario.owaspCategory}</dd>
            </div>
            <div>
              <dt>Vulnerable files</dt>
              <dd>{scenario.vulnerableFiles?.join(", ") || "n/a"}</dd>
            </div>
            <div>
              <dt>Fixed files</dt>
              <dd>{scenario.fixedFiles?.join(", ") || "n/a"}</dd>
            </div>
            <div>
              <dt>Remediation</dt>
              <dd>{scenario.remediation}</dd>
            </div>
          </dl>
        </article>
      ))}
    </div>
  );
}
