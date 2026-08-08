/**
 * Reads the one-time token out of a mailed link.
 *
 * Mailed links put it in the FRAGMENT (`/reset#token=…`). A fragment is never
 * transmitted to the server, so it cannot land in the ALB access log, a proxy
 * log, or a Referer header — which matters because a reset token is still live
 * when the page loads (it is spent later, by POST /api/auth/reset).
 *
 * The query string is deliberately not read as a fallback. Accepting `?token=`
 * would keep the original exposure alive for as long as any link carrying one
 * exists, and there is no point at which the reader could tell a stale mailed
 * link from an attacker replaying a token lifted out of a log. Links mailed
 * before this change stop resolving; the recovery is to request a new one.
 *
 * Own file rather than a local in auth.tsx so the server test suite can import
 * it — portal/web has no test runner of its own.
 */
export function linkToken(href: string): string {
  return new URLSearchParams(new URL(href).hash.slice(1)).get('token') ?? '';
}
