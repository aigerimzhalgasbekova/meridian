#!/usr/bin/env bash
# End-to-end smoke against the deployed AWS stack, over real DNS:
# TLS + health on every public host, OIDC discovery, JWKS (idp -> keysmith
# over Cloud Map), a full authorization-code login, userinfo, refresh
# rotation + replay/family-revocation, portal API, bridge + console pages.
#
#   MERIDIAN_DOMAIN=example.com ./live-smoke.sh
#
# Before DNS records exist, pin every hostname to the ALB instead
# (TLS still validates against the wildcard cert):
#
#   MERIDIAN_DOMAIN=example.com ALB_HOST=<name>.elb.amazonaws.com ./live-smoke.sh
#
# Exercises the seeded demo realm (IDP_SEED_DEMO=1): alice / password123.
set -euo pipefail

DOMAIN=${MERIDIAN_DOMAIN:?set MERIDIAN_DOMAIN, e.g. example.com}
# seeded with a no-op flag: bash 3.2 (macOS) + set -u chokes on empty arrays
R=(-s)
if [ -n "${ALB_HOST:-}" ]; then
  ALB_IP=$(dig +short "$ALB_HOST" | head -1)
  for h in idp sso portal console; do R+=(--resolve "$h.$DOMAIN:443:$ALB_IP"); done
fi
IDP="https://idp.$DOMAIN"
REALM=demo
CLIENT_ID=web-app
CLIENT_SECRET=web-app-secret
REDIRECT_URI=http://localhost:3000/callback

JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
pass=0
step() { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok: %s\n' "$1"; pass=$((pass+1)); }
die()  { printf '   FAIL: %s\n' "$1" >&2; exit 1; }

step "TLS + health on all public hosts"
for h in idp sso portal console; do
  curl -fsS "${R[@]}" "https://$h.$DOMAIN/healthz" >/dev/null || die "$h unhealthy"
  ok "$h.$DOMAIN healthy over TLS"
done

step "idp discovery"
disco=$(curl -fsS "${R[@]}" "$IDP/realms/$REALM/.well-known/openid-configuration") || die "discovery unreachable"
echo "$disco" | grep -q "\"issuer\":\"$IDP/realms/$REALM\"" || die "wrong issuer: $disco"
ok "discovery served, issuer = $IDP/realms/$REALM"

step "realm JWKS (idp -> keysmith over CloudMap)"
jwks=$(curl -fsS "${R[@]}" "$IDP/realms/$REALM/.well-known/jwks.json") || die "jwks unreachable"
echo "$jwks" | grep -q '"keys"' || die "no keys: $jwks"
ok "JWKS re-published by idp (keysmith reachable inside VPC)"

step "authorize -> login"
STATE=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
AUTHZ="$IDP/realms/$REALM/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid+profile+email+offline_access&state=$STATE"
page=$(curl -fsS "${R[@]}" -c "$JAR" "$AUTHZ") || die "authorize unreachable"
csrf=$(echo "$page" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -1)
return_to=$(echo "$page" | sed -n 's/.*name="return_to" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$csrf" ] || die "no csrf on login page"
ok "login form rendered"

loc=$(curl -fsS "${R[@]}" -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=alice" \
  --data-urlencode "password=password123" \
  --data-urlencode "csrf_token=$csrf" \
  --data-urlencode "return_to=$return_to" \
  "$IDP/realms/$REALM/login")
[ -n "$loc" ] || die "login rejected"
ok "alice logged in"

step "code issued"
loc=$(curl -fsS "${R[@]}" -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' "$AUTHZ")
case "$loc" in "$REDIRECT_URI"*code=*) : ;; *) die "no code: $loc" ;; esac
code=$(echo "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
got_state=$(echo "$loc" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
[ "$got_state" = "$STATE" ] || die "state mismatch"
ok "authorization code issued, state round-tripped"

step "token endpoint (signed by keysmith)"
tokens=$(curl -fsS "${R[@]}" -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$code" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  "$IDP/realms/$REALM/token") || die "token exchange failed"
echo "$tokens" | grep -q '"access_token"' || die "no access_token"
echo "$tokens" | grep -q '"id_token"' || die "no id_token"
echo "$tokens" | grep -q '"refresh_token"' || die "no refresh_token"
access_token=$(echo "$tokens" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
refresh_token=$(echo "$tokens" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
ok "access + id + refresh tokens issued"

step "userinfo"
ui=$(curl -fsS "${R[@]}" -H "Authorization: Bearer $access_token" "$IDP/realms/$REALM/userinfo") || die "userinfo rejected"
echo "$ui" | grep -q '"sub"' || die "no sub"
ok "userinfo: $(echo "$ui" | head -c 100)"

step "refresh rotation + reuse detection"
rot=$(curl -fsS "${R[@]}" -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$refresh_token" \
  "$IDP/realms/$REALM/token") || die "refresh failed"
echo "$rot" | grep -q '"refresh_token"' || die "no rotated token"
ok "refresh token rotated"
replay=$(curl -s "${R[@]}" -u "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$refresh_token" \
  "$IDP/realms/$REALM/token")
echo "$replay" | grep -q 'invalid_grant' || die "replay was not rejected: $replay"
ok "replayed refresh token rejected (family revoked)"

step "portal API (Postgres-backed)"
me=$(curl -s -o /dev/null -w '%{http_code}' "${R[@]}" "https://portal.$DOMAIN/api/me")
[ "$me" = "401" ] || die "portal /api/me expected 401, got $me"
ok "portal API up (unauthenticated 401 as designed)"

step "bridge + console pages"
curl -fsS "${R[@]}" "https://sso.$DOMAIN/" | grep -qi "sign in\|provider" || die "bridge home broken"
ok "bridge provider picker renders"
curl -fsS "${R[@]}" "https://console.$DOMAIN/" >/dev/null || die "console not serving"
ok "console SPA serves"

printf '\nLIVE SMOKE PASSED (%d checks)\n' "$pass"
