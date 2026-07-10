// TraceView renders an rbac.Decision as an indented tree: verdict, the rule
// that decided it, then every assignment considered — including scope
// mismatches — with the role chain walked and the rules that matched. This
// is the console's centerpiece; the 403 error box reuses it so a denied
// admin sees exactly why.
import type { Decision, Match } from "./api";
import { scopeLabel } from "./api";

const EFFECT_LABEL: Record<Decision["effect"], string> = {
  allow: "ALLOWED",
  deny: "DENIED (explicit deny)",
  default_deny: "DENIED (no matching grant — default deny)",
};

function DeciderLine({ d }: { d: Match }) {
  return (
    <div className="trace-decider">
      decided by <b>{d.effect}</b> rule <code>{d.rule}</code> in role <code>{d.role}</code> via
      assignment <code>{d.assignment.subject}</code> → <code>{d.assignment.role}</code> @{" "}
      <code>{scopeLabel(d.assignment.scope)}</code>
    </div>
  );
}

export function TraceView({ decision }: { decision: Decision }) {
  return (
    <div className={`trace ${decision.allowed ? "trace-allow" : "trace-deny"}`}>
      <div className="trace-verdict">
        <code>{decision.subject}</code> · <code>{decision.permission}</code> @{" "}
        <code>{scopeLabel(decision.scope)}</code> → <b>{EFFECT_LABEL[decision.effect]}</b>
      </div>
      {decision.decider && <DeciderLine d={decision.decider} />}
      <ul className="trace-tree">
        {(decision.trace ?? []).map((at, i) => (
          <li key={i}>
            <span className={at.scope_match ? "" : "trace-skip"}>
              assignment: <code>{at.assignment.role}</code> @{" "}
              <code>{scopeLabel(at.assignment.scope)}</code>
              {!at.scope_match && " — skipped: scope does not cover this check"}
            </span>
            {at.scope_match && (
              <ul>
                {(at.chain ?? []).map((rt) => (
                  <li key={rt.role}>
                    role <code>{rt.role}</code>
                    <ul>
                      {(rt.matched_denies ?? []).map((p) => (
                        <li key={`d${p}`} className="trace-rule-deny">
                          deny <code>{p}</code> matches
                        </li>
                      ))}
                      {(rt.matched_grants ?? []).map((p) => (
                        <li key={`g${p}`} className="trace-rule-allow">
                          grant <code>{p}</code> matches
                        </li>
                      ))}
                      {!rt.matched_grants?.length && !rt.matched_denies?.length && (
                        <li className="trace-skip">no matching rules</li>
                      )}
                    </ul>
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
        {!decision.trace?.length && (
          <li className="trace-skip">no assignments exist for this subject</li>
        )}
      </ul>
    </div>
  );
}
