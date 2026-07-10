# Local stack (docker compose)

All seven Meridian services plus Postgres and Redis, wired the way the AWS
deployment wires them — same env vars, same tokens, same ports.

## Boot

```sh
cd platform/compose
cp .env.example .env          # replace every change-me. The file header names the
                              # default generator (openssl rand -hex 32); PORTAL_TOTP_KEK
                              # is the exception — openssl rand -base64 32, exactly 32 bytes
docker compose up -d --build
./smoke.sh                    # end-to-end: JWKS -> discovery -> auth-code flow
```

Build note: `idp` and `bridge` build from the **repo root** context (their
Dockerfiles `COPY keysmith/` next to their own module because of the
`go.mod replace` directive); everything else builds from its own directory.
The compose file already sets the right contexts.

## Boot order

`postgres` and `redis` start first (healthcheck-gated). `idp` waits for both
postgres and keysmith; `portal` waits for postgres (its schema is applied by
`initdb/01-portal.sh` on first boot). The Go services ship on distroless
images (no shell), so they have no container healthchecks — `smoke.sh` is the
health probe.

## URLs

| Service  | URL | Notes |
|----------|-----|-------|
| idp      | http://localhost:8080 | discovery: `/realms/demo/.well-known/openid-configuration`; alice / password123 |
| keysmith | http://localhost:8081 | JWKS: `/.well-known/jwks.json` |
| sessiond | http://localhost:8082 | browser demo at `/demo` |
| bridge   | http://localhost:8083 | dev mode; full SSO click-through only works in-network (fake upstream binds a random in-container port) |
| sentinel | http://localhost:8084 | API needs `Authorization: Bearer $SENTINEL_TOKEN` |
| console  | http://localhost:8085 | demo personas: `GET /v1/dev/tokens` |
| portal   | http://localhost:3000 | emails land in the container's `outbox/` dir |

## Dev-mode trade-offs (deliberate, local-only)

- keysmith: in-memory keystore — keys regenerate on restart.
- idp: `IDP_DEV_MODE=1` seeds the demo realm smoke.sh needs; set
  `IDP_DEV_MODE=0` in `.env` to run against Postgres instead (idp migrates
  itself; no demo realm, so smoke.sh's flow steps won't pass). An empty value
  does NOT work: compose's `${IDP_DEV_MODE:-1}` substitutes the default on
  empty.
- sentinel: audit chain in RAM (`SENTINEL_AUDIT_PATH=memory`).
- console/bridge: dev mode (seeded personas / fake OIDC upstream).

The AWS deployment (see `../terraform/`) runs none of these shortcuts.
