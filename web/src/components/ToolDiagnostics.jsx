export default function ToolDiagnostics({ diagnostics }) {
  if (!diagnostics.length) {
    return <div className="empty-inline">No scanner diagnostics have been generated yet.</div>;
  }

  return (
    <div className="diagnostic-list">
      {diagnostics.map((item) => (
        <article className="diagnostic-card" key={item.tool}>
          <div className="diagnostic-heading">
            <span className="badge tool">{item.tool}</span>
            <span className={`badge status ${String(item.status).toLowerCase()}`}>{item.status}</span>
          </div>
          <p>{item.message}</p>
          <dl>
            <div>
              <dt>Raw output</dt>
              <dd>{item.rawOutputPath || "n/a"}</dd>
            </div>
            {item.details ? (
              <div>
                <dt>Details</dt>
                <dd className="details-text">{item.details}</dd>
              </div>
            ) : null}
          </dl>
        </article>
      ))}
    </div>
  );
}
