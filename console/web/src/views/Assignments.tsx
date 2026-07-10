import { useState } from "react";
import { api, scopeLabel } from "../api";
import { ErrorBox, useLoad } from "../ui";

export function AssignmentsView() {
  const { data: assignments, error, reload, setError } = useLoad(api.assignments);
  const { data: roles } = useLoad(api.roles);
  const [subject, setSubject] = useState("");
  const [role, setRole] = useState("");
  const [realm, setRealm] = useState("");

  const create = () =>
    api
      .assign({ subject, role, scope: realm ? { realm } : {} })
      .then(() => {
        setSubject("");
        reload();
      })
      .catch(setError);

  return (
    <section>
      <h2>Assignments</h2>
      <ErrorBox error={error} onDismiss={() => setError(null)} />
      <div className="form-row">
        <input
          placeholder="subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="">role…</option>
          {(roles ?? []).map((r) => (
            <option key={r.name} value={r.name}>
              {r.name}
            </option>
          ))}
        </select>
        <input
          placeholder="realm (empty = global)"
          value={realm}
          onChange={(e) => setRealm(e.target.value)}
        />
        <button className="btn btn-primary" disabled={!subject || !role} onClick={create}>
          assign
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Subject</th>
            <th>Role</th>
            <th>Scope</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {(assignments ?? []).map((a, i) => (
            <tr key={i}>
              <td>
                <code>{a.subject}</code>
              </td>
              <td>
                <code>{a.role}</code>
              </td>
              <td>
                <span className="badge">{scopeLabel(a.scope)}</span>
              </td>
              <td>
                <button
                  className="btn btn-danger"
                  onClick={() => api.revokeAssignment(a).then(reload, setError)}
                >
                  revoke
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
