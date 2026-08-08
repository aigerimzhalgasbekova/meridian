/**
 * Reads the one-time token out of a mailed link.
 *
 * Mailed links put it in the FRAGMENT (`/reset#token=…`). A fragment is never
 * transmitted to the server, so it cannot land in the ALB access log, a proxy
 * log, or a Referer header — which matters because a reset token is still live
 * when the page loads (it is spent later, by POST /api/auth/reset).
 *
 * The query string is read only as a TRANSITION fallback: links mailed before
 * the fragment change carry `?token=` with a 24h TTL, and the portal has no
 * resend route for signup verification, so dropping them cold would strand
 * those accounts unverified with no self-service recovery. Delete the fallback
 * once that TTL has passed post-deploy — keeping it longer would keep the
 * original log-exposure alive for as long as any link carrying one exists.
 *
 * Own file rather than a local in auth.tsx so the server test suite can import
 * it — portal/web has no test runner of its own.
 */
export function linkToken(href: string): string {
  const u = new URL(href);
  return new URLSearchParams(u.hash.slice(1)).get('token') ?? u.searchParams.get('token') ?? '';
}
