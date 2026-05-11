export default function ScenarioCatalog({ scenarios }) {
  if (!scenarios.length) {
    return <div className="empty-inline">No scenarios are available yet.</div>;
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
              <dt>Representative CVSS</dt>
              <dd>
                {scenario.cvss
                  ? `${scenario.cvss.baseScore} ${scenario.cvss.severity} (${scenario.cvss.confidence})`
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
