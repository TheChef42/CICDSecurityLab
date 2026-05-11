function SeverityBadge({ severity }) {
  return <span className={`badge severity ${String(severity).toLowerCase()}`}>{severity}</span>;
}

function ImpactBadge({ finding }) {
  if (!finding.mapped) return null;
  const level = finding.impactLevel || "UNKNOWN";
  const score = Number(finding.impactScore);
  const scoreText = Number.isFinite(score) && score > 0 ? score.toFixed(1).replace(/\.0$/, "") : "n/a";
  return (
    <span className={`badge impact ${String(level).toLowerCase()}`}>
      CVSS {scoreText} {level}
    </span>
  );
}

export default function RawFindings({ findings }) {
  if (!findings.length) {
    return <div className="empty-inline">No findings match the current filters.</div>;
  }

  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <article className="finding-card" key={finding.id}>
          <div className="finding-topline">
            <span className="badge tool">{finding.tool}</span>
            <SeverityBadge severity={finding.severity} />
            <span className={finding.mapped ? "badge mapped" : "badge unmapped"}>
              {finding.mapped ? finding.scenarioId : "UNMAPPED"}
            </span>
            {finding.duplicate ? <span className="badge unmapped">duplicate {finding.duplicateIndex}/{finding.duplicateCount}</span> : null}
            {finding.coverageExtra ? <span className="badge extra">extra raw finding</span> : null}
            <ImpactBadge finding={finding} />
          </div>
          <h3>{finding.title || "Unmapped finding"}</h3>
          <dl className="finding-meta">
            <div>
              <dt>File</dt>
              <dd>{finding.file || "n/a"}</dd>
            </div>
            <div>
              <dt>Line</dt>
              <dd>{finding.line || "n/a"}</dd>
            </div>
            <div>
              <dt>CWE</dt>
              <dd>{finding.cwe}</dd>
            </div>
            <div>
              <dt>OWASP</dt>
              <dd>{finding.owaspCategory}</dd>
            </div>
            <div>
              <dt>Rule</dt>
              <dd>{finding.ruleId || "n/a"}</dd>
            </div>
            <div>
              <dt>Impact</dt>
              <dd>
                {finding.mapped
                  ? `${finding.impactLevel || "UNKNOWN"} from ${finding.impactSource || "scenario CVSS"}`
                  : "n/a"}
              </dd>
            </div>
          </dl>
          <p className="finding-message">{finding.message || "No tool message provided."}</p>
          {finding.coverageExtra ? (
            <p className="finding-note">{finding.coverageExtraReason}</p>
          ) : null}
        </article>
      ))}
    </div>
  );
}
