/**
 * Reads the one-time token out of a mailed link.
 *
 * Mailed links put it in the FRAGMENT (`/reset#token=…`). A fragment is never
 * transmitted to the server, so it cannot land in the ALB access log, a proxy
 * log, or a Referer header — which matters because a reset token is still live
 * when the page loads (it is spent later, by POST /api/auth/reset).
 *
 * ponytail: the query string is still read as a fallback, because links mailed
 * before this change are already sitting in inboxes and carry `?token=`. Those
 * links keep reaching the ALB access log, so delete that half — and the
 * matching caveats in platform/terraform/envs/dev/main.tf and .trivyignore —
 * once the longest token TTL (verify-email, 24h) has passed since deploy.
 *
 * Own file rather than a local in auth.tsx so the server test suite can import
 * it — portal/web has no test runner of its own.
 */
export function linkToken(href: string): string {
  const u = new URL(href);
  return new URLSearchParams(u.hash.slice(1)).get('token') ?? u.searchParams.get('token') ?? '';
}
