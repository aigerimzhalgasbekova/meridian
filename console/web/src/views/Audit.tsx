import { api } from "../api";
import { ErrorBox, useLoad } from "../ui";

export function AuditView() {
  const { data: events, error, setError } = useLoad(api.audit);
  return (
    <section>
      <h2>Audit trail</h2>
      <p className="muted">Every mutation attempt, allowed or denied. Newest first.</p>
      <ErrorBox error={error} onDismiss={() => setError(null)} />
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Scope</th>
            <th>Outcome</th>
          </tr>
        </thead>
        <tbody>
          {(events ?? []).map((e, i) => (
            <tr key={i}>
              <td>{new Date(e.time).toLocaleString()}</td>
              <td>
                <code>{e.actor}</code>
              </td>
              <td>{e.action}</td>
              <td>
                <code>{e.target}</code>
              </td>
              <td>
                <span className="badge">{e.scope}</span>
              </td>
              <td>
                <span className={`badge ${e.allowed ? "badge-allow" : "badge-deny"}`}>
                  {e.allowed ? "allowed" : "denied"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
