import { useMemo, useState } from "react";
import type { Role } from "../api";
import { api } from "../api";
import { ErrorBox, useLoad } from "../ui";

// Permissions matrix: rows = resources, columns = actions, derived from the
// server's permission catalog plus the wildcard column.
function Matrix({
  permissions,
  selected,
  onToggle,
}: {
  permissions: string[];
  selected: Set<string>;
  onToggle: (p: string) => void;
}) {
  const { resources, actions } = useMemo(() => {
    const res = new Set<string>();
    const act = new Set<string>();
    for (const p of permissions) {
      const [r, a] = p.split(":");
      if (r && a) {
        res.add(r);
        act.add(a);
      }
    }
    return { resources: [...res].sort(), actions: [...act].sort() };
  }, [permissions]);

  const valid = new Set(permissions);
  return (
    <table className="matrix">
      <thead>
        <tr>
          <th></th>
          {actions.map((a) => (
            <th key={a}>{a}</th>
          ))}
          <th>*</th>
        </tr>
      </thead>
      <tbody>
        {resources.map((r) => (
          <tr key={r}>
            <th>{r}</th>
            {actions.map((a) => {
              const p = `${r}:${a}`;
              return (
                <td key={a}>
                  {valid.has(p) && (
                    <input
                      type="checkbox"
                      checked={selected.has(p) || selected.has(`${r}:*`) || selected.has("*:*")}
                      disabled={selected.has(`${r}:*`) || selected.has("*:*")}
                      onChange={() => onToggle(p)}
                    />
                  )}
                </td>
              );
            })}
            <td>
              <input
                type="checkbox"
                checked={selected.has(`${r}:*`) || selected.has("*:*")}
                disabled={selected.has("*:*")}
                onChange={() => onToggle(`${r}:*`)}
              />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const EMPTY = { name: "", description: "", extends: "", grants: [] as string[], denies: [] as string[] };

export function RolesView() {
  const { data: roles, error, reload, setError } = useLoad(api.roles);
  const { data: permissions } = useLoad(api.permissions);
  const [draft, setDraft] = useState(EMPTY);
  const [editing, setEditing] = useState(false); // true = PUT existing

  const toggle = (list: string[], p: string) =>
    list.includes(p) ? list.filter((x) => x !== p) : [...list, p];

  const save = () => {
    const { extends: ext, ...rest } = draft;
    const body = ext ? { ...rest, extends: ext } : rest;
    (editing ? api.updateRole(body) : api.createRole(body))
      .then(() => {
        setDraft(EMPTY);
        setEditing(false);
        reload();
      })
      .catch(setError);
  };

  return (
    <section>
      <h2>Roles</h2>
      <ErrorBox error={error} onDismiss={() => setError(null)} />
      <table>
        <thead>
          <tr>
            <th>Role</th>
            <th>Extends</th>
            <th>Grants</th>
            <th>Denies</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(roles ?? []).map((r: Role) => (
            <tr key={r.name}>
              <td>
                <code>{r.name}</code> {r.builtin && <span className="badge">builtin</span>}
                <div className="muted">{r.description}</div>
              </td>
              <td>{r.extends && <code>{r.extends}</code>}</td>
              <td>
                {r.grants.map((p) => (
                  <code key={p} className="perm perm-allow">
                    {p}
                  </code>
                ))}
              </td>
              <td>
                {(r.denies ?? []).map((p) => (
                  <code key={p} className="perm perm-deny">
                    {p}
                  </code>
                ))}
              </td>
              <td>
                {!r.builtin && (
                  <>
                    <button
                      className="btn"
                      onClick={() => {
                        setDraft({
                          name: r.name,
                          description: r.description ?? "",
                          extends: r.extends ?? "",
                          grants: [...r.grants],
                          denies: [...(r.denies ?? [])],
                        });
                        setEditing(true);
                      }}
                    >
                      edit
                    </button>{" "}
                    <button
                      className="btn btn-danger"
                      onClick={() => api.deleteRole(r.name).then(reload, setError)}
                    >
                      delete
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>{editing ? `Edit role: ${draft.name}` : "New custom role"}</h3>
      <div className="form-row">
        <input
          placeholder="role-name"
          value={draft.name}
          disabled={editing}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
        />
        <input
          placeholder="description"
          value={draft.description}
          onChange={(e) => setDraft({ ...draft, description: e.target.value })}
        />
        <select
          value={draft.extends}
          onChange={(e) => setDraft({ ...draft, extends: e.target.value })}
        >
          <option value="">extends: none</option>
          {(roles ?? [])
            .filter((r) => r.name !== draft.name)
            .map((r) => (
              <option key={r.name} value={r.name}>
                extends: {r.name}
              </option>
            ))}
        </select>
      </div>
      <div className="matrix-pair">
        <div>
          <h4>Grants</h4>
          <Matrix
            permissions={permissions ?? []}
            selected={new Set(draft.grants)}
            onToggle={(p) => setDraft({ ...draft, grants: toggle(draft.grants, p) })}
          />
        </div>
        <div>
          <h4>Denies (override every allow)</h4>
          <Matrix
            permissions={permissions ?? []}
            selected={new Set(draft.denies)}
            onToggle={(p) => setDraft({ ...draft, denies: toggle(draft.denies, p) })}
          />
        </div>
      </div>
      <button className="btn btn-primary" disabled={!draft.name} onClick={save}>
        {editing ? "save changes" : "create role"}
      </button>{" "}
      {editing && (
        <button
          className="btn btn-ghost"
          onClick={() => {
            setDraft(EMPTY);
            setEditing(false);
          }}
        >
          cancel
        </button>
      )}
    </section>
  );
}
