import { useEffect, useState } from "react";
import { api, setToken } from "./api";
import { AssignmentsView } from "./views/Assignments";
import { AuditView } from "./views/Audit";
import { ExplainView } from "./views/Explain";
import { RolesView } from "./views/Roles";
import { UsersView } from "./views/Users";

const TABS = ["users", "roles", "assignments", "explain", "audit"] as const;
type Tab = (typeof TABS)[number];

export function App() {
  const [tab, setTab] = useState<Tab>("explain");
  const [personas, setPersonas] = useState<Record<string, string> | null>(null);
  const [who, setWho] = useState(localStorage.getItem("console_persona") ?? "");
  const [manual, setManual] = useState("");

  // Dev mode exposes pre-minted persona tokens; production pastes a token.
  useEffect(() => {
    api.devTokens().then(setPersonas, () => setPersonas(null));
  }, []);

  const pick = (name: string) => {
    if (personas?.[name]) {
      setToken(personas[name]);
      setWho(name);
      localStorage.setItem("console_persona", name);
    }
  };

  return (
    <>
      <header>
        <h1>
          Meridian <span className="accent">Console</span>
        </h1>
        <div className="who">
          {personas ? (
            <select value={who} onChange={(e) => pick(e.target.value)}>
              <option value="">act as…</option>
              {Object.keys(personas)
                .sort()
                .map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
            </select>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                setToken(manual);
                setWho("token set");
              }}
            >
              <input
                placeholder="paste bearer token"
                value={manual}
                onChange={(e) => setManual(e.target.value)}
              />
              <button className="btn" type="submit">
                use
              </button>
            </form>
          )}
        </div>
      </header>
      <nav>
        {TABS.map((t) => (
          <button
            key={t}
            className={t === tab ? "tab tab-active" : "tab"}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </nav>
      <main key={`${tab}:${who}`}>
        {tab === "users" && <UsersView />}
        {tab === "roles" && <RolesView />}
        {tab === "assignments" && <AssignmentsView />}
        {tab === "explain" && <ExplainView />}
        {tab === "audit" && <AuditView />}
      </main>
    </>
  );
}
