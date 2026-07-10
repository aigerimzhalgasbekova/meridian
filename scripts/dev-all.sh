#!/usr/bin/env bash
# Boots every Meridian service in its zero-dependency dev mode — no Docker,
# no Postgres, no Redis, no cloud accounts. Ctrl-C shuts everything down.
#
#   keysmith :8081   in-memory keystore
#   idp      :8080   in-memory store, seeded "demo" realm (alice/password123)
#   sessiond :8082   embedded miniredis, browser demo at /demo
#   bridge   :8083   built-in fake OIDC upstreams
#   sentinel :8084   in-memory audit chain (API token: dev-token)
#   console  :8085   seeded demo world, personas at /v1/dev/tokens
#   portal   :3000   in-memory store, mail to portal/server/outbox/ (web :5173)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v go >/dev/null 2>&1 && [ -x "$HOME/sdk/go1.26.5/bin/go" ]; then
  export PATH="$HOME/sdk/go1.26.5/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || { echo "error: go not found on PATH" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "error: npm not found on PATH" >&2; exit 1; }

LOG_DIR="${DEV_ALL_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/meridian-dev.XXXXXX")}"
echo "logs: $LOG_DIR"

PIDS=()
cleanup() {
  trap - INT TERM EXIT
  echo
  echo "shutting down..."
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  # Give everyone a moment to exit gracefully, then force-kill stragglers.
  for _ in $(seq 1 20); do
    alive=0
    for pid in "${PIDS[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
    [ "$alive" = 0 ] && break
    sleep 0.25
  done
  for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
  echo "done."
}
trap cleanup INT TERM EXIT

echo "building Go services..."
(cd "$ROOT/keysmith" && go build -o bin/keysmithd ./cmd/keysmithd)
(cd "$ROOT/idp"      && go build -o bin/idpd      ./cmd/idpd)
(cd "$ROOT/sessiond" && go build -o bin/sessiond  ./cmd/sessiond)
(cd "$ROOT/bridge"   && go build -o bin/bridged   ./cmd/bridged)
(cd "$ROOT/sentinel" && go build -o bin/sentineld ./cmd/sentineld)
(cd "$ROOT/console"  && go build -o bin/consoled  ./cmd/consoled)

start() { # start <name> <dir> <cmd...>
  local name=$1 dir=$2; shift 2
  (cd "$dir" && exec "$@") >"$LOG_DIR/$name.log" 2>&1 &
  PIDS+=($!)
  echo "  $name (pid $!)"
}

echo "starting services..."
KEYSMITH_DEV_MODE=1 KEYSMITH_SIGNER_TOKENS=dev-signer KEYSMITH_ADMIN_TOKENS=dev-admin \
  start keysmith "$ROOT/keysmith" ./bin/keysmithd
IDP_DEV_MODE=1 IDP_KEYSMITH_TOKEN=dev-signer IDP_REGISTRATION_TOKEN=dev-reg \
  start idp "$ROOT/idp" ./bin/idpd
SESSIOND_DEV_MODE=1 SESSIOND_API_TOKENS=dev-service \
  start sessiond "$ROOT/sessiond" ./bin/sessiond
BRIDGE_DEV_MODE=1 BRIDGE_ADDR=:8083 \
  start bridge "$ROOT/bridge" ./bin/bridged
SENTINEL_TOKEN=dev-token SENTINEL_AUDIT_PATH=memory \
  start sentinel "$ROOT/sentinel" ./bin/sentineld
CONSOLE_WEB=""
[ -d "$ROOT/console/web/dist" ] && CONSOLE_WEB="$ROOT/console/web/dist"
CONSOLE_DEV_MODE=1 CONSOLE_WEB_DIR="$CONSOLE_WEB" \
  start console "$ROOT/console" ./bin/consoled

if [ ! -d "$ROOT/portal/node_modules" ]; then
  echo "portal: installing npm dependencies (first run)..."
  (cd "$ROOT/portal" && npm install) >"$LOG_DIR/portal-install.log" 2>&1
fi
start portal "$ROOT/portal" npm run dev

wait_healthy() { # wait_healthy <name> <url>
  local i
  for i in $(seq 1 60); do
    if curl -fsS -o /dev/null --max-time 2 "$2" 2>/dev/null; then
      printf '  %-8s ok   %s\n' "$1" "$2"; return 0
    fi
    sleep 0.5
  done
  printf '  %-8s FAIL %s  (see %s/%s.log)\n' "$1" "$2" "$LOG_DIR" "$1" >&2
  return 1
}

echo "waiting for health..."
wait_healthy keysmith http://localhost:8081/healthz
wait_healthy idp      http://localhost:8080/healthz
wait_healthy sessiond http://localhost:8082/healthz
wait_healthy bridge   http://localhost:8083/healthz
wait_healthy sentinel http://localhost:8084/healthz
wait_healthy console  http://localhost:8085/healthz
wait_healthy portal   http://localhost:3000/healthz

cat <<EOF

Meridian dev stack is up:

  Service   URL                     Try
  keysmith  http://localhost:8081   /.well-known/jwks.json
  idp       http://localhost:8080   /realms/demo/.well-known/openid-configuration  (alice / password123)
  sessiond  http://localhost:8082   /demo/  (alice/wonderland, bob/builder)
  bridge    http://localhost:8083   sign in via the built-in fake upstream
  sentinel  http://localhost:8084   /v1/* with 'Authorization: Bearer dev-token'
  console   http://localhost:8085   /v1/dev/tokens for personas
  portal    http://localhost:3000   API; web UI at http://localhost:5173

Ctrl-C to stop everything.  Logs: $LOG_DIR
EOF

wait
