import { useState } from "react";
import type { Decision } from "../api";
import { api } from "../api";
import { TraceView } from "../Trace";
import { ErrorBox, useLoad } from "../ui";

// The star of the console: ask "can <subject> do <permission> in <scope>?"
// and get the engine's full decision trace rendered as a tree.
export function ExplainView() {
  const { data: permissions } = useLoad(api.permissions);
  const [subject, setSubject] = useState("");
  const [permission, setPermission] = useState("");
  const [realm, setRealm] = useState("");
  const [decision, setDecision] = useState<Decision | null>(null);
  const [error, setError] = useState<unknown>(null);

  const run = () =>
    api.explain(subject, permission, realm).then(
      (d) => {
        setDecision(d);
        setError(null);
      },
      (e: unknown) => {
        setDecision(null);
        setError(e);
      },
    );

  return (
    <section>
      <h2>Explain access</h2>
      <p className="muted">
        Ask the exact question the API asks on every request: is this subject allowed this
        permission at this scope — and why?
      </p>
      <div className="form-row">
        <input
          placeholder="subject (e.g. alice)"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
        <input
          list="perm-catalog"
          placeholder="permission (e.g. users:write)"
          value={permission}
          onChange={(e) => setPermission(e.target.value)}
        />
        <datalist id="perm-catalog">
          {(permissions ?? []).map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
        <input
          placeholder="realm (empty = global)"
          value={realm}
          onChange={(e) => setRealm(e.target.value)}
        />
        <button
          className="btn btn-primary"
          disabled={!subject || !permission}
          onClick={run}
        >
          explain
        </button>
      </div>
      <ErrorBox error={error} onDismiss={() => setError(null)} />
      {decision && <TraceView decision={decision} />}
    </section>
  );
}
