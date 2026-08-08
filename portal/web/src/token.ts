/**
 * Reads the one-time token out of a mailed link.
 *
 * Mailed links put it in the FRAGMENT (`/reset#token=…`). A fragment is never
 * transmitted to the server, so it cannot land in the ALB access log, a proxy
 * log, or a Referer header — which matters because a reset token is still live
 * when the page loads (it is spent later, by POST /api/auth/reset).
 *
 * `?token=` is deliberately NOT read: honouring it would keep the log-exposure
 * path alive for anyone who can put a token there.
 *
 * Own file rather than a local in auth.tsx so the server test suite can import
 * it — portal/web has no test runner of its own.
 */
export function linkToken(href: string): string {
  return new URLSearchParams(new URL(href).hash.slice(1)).get('token') ?? '';
}
