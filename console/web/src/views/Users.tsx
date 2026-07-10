import { Fragment, useState } from "react";
import type { Session } from "../api";
import { api } from "../api";
import { ErrorBox, useLoad } from "../ui";

function SessionRows({ userID, onError }: { userID: string; onError: (e: unknown) => void }) {
  const { data: sessions, reload } = useLoad<Session[]>(() => api.sessions(userID), [userID]);
  if (!sessions) return null;
  if (sessions.length === 0)
    return (
      <tr className="subrow">
        <td colSpan={5}>no active sessions</td>
      </tr>
    );
  return (
    <>
      {sessions.map((s) => (
        <tr className="subrow" key={s.id}>
          <td colSpan={2}>
            session <code>{s.id}</code>
          </td>
          <td>{new Date(s.created_at).toLocaleString()}</td>
          <td>{s.ip}</td>
          <td>
            <button
              className="btn btn-danger"
              onClick={() => api.revokeSession(s.id).then(reload, onError)}
            >
              revoke
            </button>
          </td>
        </tr>
      ))}
    </>
  );
}

export function UsersView() {
  const { data: users, error, reload, setError } = useLoad(api.users);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <section>
      <h2>Users</h2>
      <ErrorBox error={error} onDismiss={() => setError(null)} />
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Email</th>
            <th>Realm</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(users ?? []).map((u) => (
            <Fragment key={u.id}>
              <tr>
                <td>
                  {u.name} <code>{u.id}</code>
                </td>
                <td>{u.email}</td>
                <td>
                  <span className="badge">{u.realm}</span>
                </td>
                <td>
                  <span className={`badge ${u.disabled ? "badge-deny" : "badge-allow"}`}>
                    {u.disabled ? "disabled" : "active"}
                  </span>
                </td>
                <td>
                  <button
                    className="btn"
                    onClick={() =>
                      api.setUserDisabled(u.id, !u.disabled).then(reload, setError)
                    }
                  >
                    {u.disabled ? "enable" : "disable"}
                  </button>{" "}
                  <button
                    className="btn btn-ghost"
                    onClick={() => setOpen(open === u.id ? null : u.id)}
                  >
                    {open === u.id ? "hide sessions" : "sessions"}
                  </button>
                </td>
              </tr>
              {open === u.id && <SessionRows userID={u.id} onError={setError} />}
            </Fragment>
          ))}
        </tbody>
      </table>
    </section>
  );
}
