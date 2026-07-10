// Typed client for the console API. Every response shape mirrors the Go
// structs' JSON tags exactly; ApiError carries the deny Decision on 403 so
// the UI can render *why* the caller was refused.

export interface Scope {
  realm?: string;
}

export interface Role {
  name: string;
  description?: string;
  extends?: string;
  grants: string[];
  denies?: string[];
  builtin: boolean;
}

export interface Assignment {
  subject: string;
  role: string;
  scope: Scope;
}

export interface Match {
  assignment: Assignment;
  role: string;
  rule: string;
  effect: "allow" | "deny";
}

export interface RoleTrace {
  role: string;
  matched_grants?: string[];
  matched_denies?: string[];
}

export interface AssignmentTrace {
  assignment: Assignment;
  scope_match: boolean;
  chain?: RoleTrace[];
}

export interface Decision {
  subject: string;
  permission: string;
  scope: Scope;
  allowed: boolean;
  effect: "allow" | "deny" | "default_deny";
  decider?: Match;
  trace: AssignmentTrace[] | null;
}

export interface User {
  id: string;
  email: string;
  name: string;
  realm: string;
  disabled: boolean;
}

export interface Session {
  id: string;
  user_id: string;
  created_at: string;
  ip?: string;
  user_agent?: string;
}

export interface AuditEvent {
  time: string;
  actor: string;
  action: string;
  target: string;
  scope: string;
  allowed: boolean;
  detail?: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public decision?: Decision,
  ) {
    super(message);
  }
}

let token = localStorage.getItem("console_token") ?? "";

export function setToken(t: string): void {
  token = t;
  localStorage.setItem("console_token", t);
}

export function scopeLabel(s: Scope): string {
  return s.realm ? `realm:${s.realm}` : "global";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (res.status === 204) return undefined as T;
  const data: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const e = data as { error?: string; message?: string; decision?: Decision };
    throw new ApiError(res.status, e.error ?? "error", e.message ?? res.statusText, e.decision);
  }
  return data as T;
}

export const api = {
  devTokens: () => request<Record<string, string>>("GET", "/v1/dev/tokens"),
  permissions: () =>
    request<{ permissions: string[] }>("GET", "/v1/permissions").then((r) => r.permissions),
  roles: () => request<{ roles: Role[] }>("GET", "/v1/roles").then((r) => r.roles),
  createRole: (r: Omit<Role, "builtin">) => request<Role>("POST", "/v1/roles", r),
  updateRole: (r: Omit<Role, "builtin">) =>
    request<Role>("PUT", `/v1/roles/${encodeURIComponent(r.name)}`, r),
  deleteRole: (name: string) =>
    request<void>("DELETE", `/v1/roles/${encodeURIComponent(name)}`),
  assignments: () =>
    request<{ assignments: Assignment[] }>("GET", "/v1/assignments").then((r) => r.assignments),
  assign: (a: Assignment) => request<Assignment>("POST", "/v1/assignments", a),
  revokeAssignment: (a: Assignment) => request<void>("POST", "/v1/assignments/revoke", a),
  explain: (subject: string, permission: string, realm: string) => {
    const q = new URLSearchParams({ subject, permission });
    if (realm) q.set("realm", realm);
    return request<Decision>("GET", `/v1/authz/explain?${q}`);
  },
  users: () => request<{ users: User[] }>("GET", "/v1/users").then((r) => r.users),
  setUserDisabled: (id: string, disabled: boolean) =>
    request<User>("POST", `/v1/users/${encodeURIComponent(id)}/${disabled ? "disable" : "enable"}`),
  sessions: (userID: string) =>
    request<{ sessions: Session[] }>(
      "GET",
      `/v1/users/${encodeURIComponent(userID)}/sessions`,
    ).then((r) => r.sessions),
  revokeSession: (id: string) =>
    request<void>("POST", `/v1/sessions/${encodeURIComponent(id)}/revoke`),
  audit: () => request<{ events: AuditEvent[] }>("GET", "/v1/audit").then((r) => r.events),
};
