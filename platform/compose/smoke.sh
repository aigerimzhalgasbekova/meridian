#!/usr/bin/env bash
# End-to-end smoke test against the compose stack (IDP_DEV_MODE=1 required:
# it seeds realm "demo", user alice/password123, first-party client web-app).
#
#   keysmith JWKS -> idp discovery -> full authorization-code flow
#   (login form + CSRF, code redemption, userinfo) -> sibling health checks
#
# Usage: ./smoke.sh   (after: docker compose up -d --build)
set -euo pipefail

KEYSMITH=${KEYSMITH_URL:-http://localhost:8081}
IDP=${IDP_URL:-http://localhost:8080}
REALM=demo
CLIENT_ID=web-app
CLIENT_SECRET=web-app-secret
REDIRECT_URI=http://localhost:3000/callback

JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

pass=0
step() { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok: %s\n' "$1"; pass=$((pass+1)); }
die()  { printf '   FAIL: %s\n' "$1" >&2; exit 1; }

step "keysmith JWKS"
jwks=$(curl -fsS "$KEYSMITH/.well-known/jwks.json") || die "JWKS unreachable"
echo "$jwks" | grep -q '"keys"' || die "no keys in JWKS: $jwks"
ok "JWKS served"

step "idp discovery"
disco=$(curl -fsS "$IDP/realms/$REALM/.well-known/openid-configuration") || die "discovery unreachable"
echo "$disco" | grep -q '"issuer"' || die "no issuer in discovery: $disco"
ok "discovery document served"

step "authorize -> login page"
STATE=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
AUTHZ="$IDP/realms/$REALM/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid+profile+email&state=$STATE"
page=$(curl -fsS -c "$JAR" "$AUTHZ") || die "authorize unreachable"
csrf=$(echo "$page" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -1)
return_to=$(echo "$page" | sed -n 's/.*name="return_to" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$csrf" ] || die "no csrf_token on login page"
ok "login form rendered (csrf present)"

step "login as alice"
# 303 back to the authorize URL on success; error page (200) on failure.
loc=$(curl -fsS -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=alice" \
  --data-urlencode "password=password123" \
  --data-urlencode "csrf_token=$csrf" \
  --data-urlencode "return_to=$return_to" \
  "$IDP/realms/$REALM/login")
[ -n "$loc" ] || die "login did not redirect (bad credentials or csrf)"
ok "login accepted -> $loc"

step "authorize -> code (first-party client skips consent)"
loc=$(curl -fsS -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' "$AUTHZ")
case "$loc" in
  "$REDIRECT_URI"*code=*) : ;;
  *) die "expected redirect to $REDIRECT_URI with code, got: $loc" ;;
esac
code=$(echo "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
got_state=$(echo "$loc" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
[ "$got_state" = "$STATE" ] || die "state mismatch: sent $STATE got $got_state"
ok "authorization code issued, state round-tripped"

step "redeem code at token endpoint"
tokens=$(curl -fsS -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$code" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  "$IDP/realms/$REALM/token") || die "token endpoint rejected the code"
echo "$tokens" | grep -q '"access_token"' || die "no access_token: $tokens"
echo "$tokens" | grep -q '"id_token"' || die "no id_token: $tokens"
access_token=$(echo "$tokens" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
ok "access + id tokens issued"

step "userinfo"
ui=$(curl -fsS -H "Authorization: Bearer $access_token" "$IDP/realms/$REALM/userinfo") || die "userinfo rejected token"
echo "$ui" | grep -q '"sub"' || die "no sub in userinfo: $ui"
ok "userinfo returned sub"

step "sibling services healthy"
curl -fsS "${SESSIOND_URL:-http://localhost:8082}/healthz" >/dev/null || die "sessiond unhealthy"
ok "sessiond healthy"
curl -fsS "${SENTINEL_URL:-http://localhost:8084}/healthz" >/dev/null || die "sentinel unhealthy"
ok "sentinel healthy"
curl -fsS "${CONSOLE_URL:-http://localhost:8085}/healthz" >/dev/null || die "console unhealthy"
ok "console healthy"
curl -fsS "${PORTAL_URL:-http://localhost:3000}/" >/dev/null || die "portal not serving"
ok "portal serving"
# bridge: /healthz/providers is 503 while the dev upstream breaker warms up,
# so accept any HTTP response as liveness.
bcode=$(curl -s -o /dev/null -w '%{http_code}' "${BRIDGE_URL:-http://localhost:8083}/healthz/providers")
[ "$bcode" != "000" ] || die "bridge unreachable"
ok "bridge responding (providers: HTTP $bcode)"

printf '\nSMOKE PASSED (%d checks)\n' "$pass"
