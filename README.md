# Meridian — Identity & Access Management Platform

Meridian is a portfolio of seven interlocking services (plus infrastructure and a
site) that together form a realistic, standards-aligned IAM platform — the kind of
system a mid-size company runs to centralize authentication, sessions, federation,
and access control. Each project is a standalone, reviewable codebase with its own
signature architectural challenge; together they compose into one stack you can
boot locally with a single command. Full design rationale:
[docs/design/2026-07-09-meridian-platform-design.md](docs/design/2026-07-09-meridian-platform-design.md).

## The projects

| Project | One line | Language | Signature challenge |
|---------|----------|----------|--------------------|
| [keysmith](keysmith/) | Key management & JWT signing service | Go | Zero-downtime key rotation as a state machine with enforced timing invariants; a minimal JOSE layer where historical JWT CVEs are structurally impossible |
| [idp](idp/) | Multi-tenant OAuth 2.0 / OIDC authorization server | Go | Protocol correctness under RFC scrutiny: PKCE, refresh-token rotation with family reuse detection, device flow — no implicit, no ROPC |
| [sessiond](sessiond/) | Distributed session service | Go + Redis | Cross-node revocation with a provable staleness bound; every multi-step decision is one atomic Lua script |
| [sentinel](sentinel/) | Adaptive security & compliance | Go + Python | High-throughput allow/challenge/deny decisions with a tamper-evident hash-chained audit log a stdlib-Python auditor verifies independently |
| [bridge](bridge/) | SSO federation gateway (Google / Entra ID) | Go | The RP side of OIDC from scratch; circuit breakers and stale-tolerant JWKS for upstreams you don't operate; never match accounts by email |
| [portal](portal/) | Self-service identity portal | TypeScript | Enumeration-safe password reset, hand-rolled RFC 6238 TOTP, Postgres as a job queue (`SKIP LOCKED`) |
| [console](console/) | RBAC control plane | Go + React | An authorization engine that returns a full decision *trace* with every verdict — and authorizes its own API with it |
| [platform](platform/) | Terraform (AWS), CI/CD, local compose stack | HCL / YAML | Infrastructure as a product: one security-group rule per real consumer, SSM secrets, OIDC CI federation |
| [site](site/) | Portfolio site + `/guide` engineering walkthrough | Astro | — |

## Architecture

Solid arrows are wired, running dependencies. Dashed seams are designed and
documented in code (interface + named production implementation) but deliberately
left unwired — each service's tests and dev mode run with zero external services.

```
                              ┌──────────────┐
   Google / Entra ID ◄────────│ bridge  :8083│  RP-side OIDC; verifies upstream
                              │ SSO gateway  │  ID tokens with keysmith's jose
                              └──────┬───────┘  package (module dep, not RPC)
                                     ┆ assertion signer seam: local Ed25519 key
                                     ┆ now, keysmith-backed Signer documented
                                     ▼
┌──────────────┐   OAuth2/OIDC  ┌──────────────┐  POST /v1/sign   ┌──────────────┐
│ portal :3000 │◄╌╌╌╌╌╌╌╌╌╌╌╌╌╌►│  idp   :8080 │─────────────────►│keysmith :8081│
│ self-service │  (seam: portal │ OAuth2/OIDC  │   (wired, HTTP)  │ keys + JOSE  │
│ + job queue  │  is standalone │ auth server  │                  │ JWKS for all │
└──────┬───────┘  today)        └──────┬───────┘                  └──────────────┘
       ┆                               ┆
       ┆ rate-limit middleware seam    ┆ browser-session seam
       ▼                               ▼
┌──────────────┐                ┌──────────────┐            ┌──────────────────┐
│sentinel :8084│                │sessiond :8082│            │  console  :8085  │
│ ratelimit /  │                │ Redis-backed │◄╌╌╌╌╌╌╌╌╌╌╌│ RBAC + explain   │
│ lockout /    │◄╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌│ sessions     │ session     │ seams: keysmith  │
│ audit chain  │  audit seam    └──────────────┘ provider    │ JWKS verifier,   │
└──────────────┘                                 seam        │ sentinel audit   │
                                                             └──────────────────┘
```

The one wired runtime dependency is **idp → keysmith** (idp delegates all token
signing over HTTP). Both **idp** and **bridge** additionally link keysmith's
hardened `jose` package at compile time (a `replace` directive); bridge does so
*only* that way, to verify upstream ID tokens without an RPC. sessiond and sentinel have
no in-code consumers yet — the platform Terraform deliberately grants them no
ingress until the wiring exists (see [platform/README.md](platform/README.md)).

## Quickstart

Prerequisites: Go 1.26+, Node 22+, Python 3. (No Docker, no databases — every
service has a zero-dependency dev mode.)

**Everything at once:**

```sh
./scripts/dev-all.sh     # or: make dev
```

Boots all seven services, health-checks them, and prints a URL table.
Ctrl-C stops everything. What you get:

| Service | URL | Try |
|---------|-----|-----|
| idp | http://localhost:8080 | `/realms/demo/.well-known/openid-configuration`; login `alice` / `password123` |
| keysmith | http://localhost:8081 | `/.well-known/jwks.json` |
| sessiond | http://localhost:8082 | browser demo at `/demo/` (`alice`/`wonderland`) |
| bridge | http://localhost:8083 | click through SSO against the built-in fake upstreams |
| sentinel | http://localhost:8084 | `/v1/check` with `Authorization: Bearer dev-token` |
| console | http://localhost:8085 | personas at `/v1/dev/tokens` |
| portal | http://localhost:3000 | web UI at http://localhost:5173; "emails" land in `portal/server/outbox/` |

**One service at a time** — every project has `make run` (alias of `run-dev`;
`dev` in portal):

```sh
cd keysmith && make run    # KEYSMITH_DEV_MODE=1: in-memory keystore
cd sessiond && make run    # SESSIOND_DEV_MODE=1: embedded miniredis
cd bridge   && make run    # BRIDGE_DEV_MODE=1: fake OIDC upstreams, no accounts
cd sentinel && make run    # in-memory audit chain
cd console  && make run    # seeded demo world
cd portal   && make run    # npm run dev: API + Vite web
cd idp      && make run    # IDP_DEV_MODE=1 — needs keysmith on :8081 first
```

**Full stack with real databases (Docker):**

```sh
cd platform/compose
cp .env.example .env       # replace every change-me; the file header names the generator
docker compose up -d --build
./smoke.sh                 # JWKS → discovery → full authorization-code flow
```

See [platform/compose/README.md](platform/compose/README.md).

## Tests

```sh
make test    # all six Go modules (-race) + portal (vitest) + sentinel Python suite
make check   # + go vet per module + portal typecheck
```

`make test` needs no Docker, database, or network. Current counts (from a local
run; Go numbers include subtests):

| Suite | Tests | Highlights |
|-------|------:|-----------|
| keysmith | 95 | every historical JOSE attack class as a regression test; rotation under a fake clock; concurrent signing during rotation |
| idp | 117 | full browser flows via cookie jar against an in-process keysmith; refresh-reuse detection under real concurrency |
| sessiond | 26 (+7 need Redis) | staleness-bound proof on a node missing every broadcast; parallel cap-invariant hammer on miniredis |
| sentinel (Go) | 68 | sliding-window/lockout/risk contracts; Go tests invoke the Python verifier cross-language |
| sentinel (Python) | 16 | stdlib-only chain verification of a Go-written fixture; truncation caught via the anchor sidecar |
| bridge | 57 | fake upstream misbehavior: Entra tenanted issuer, breaker transitions, stale JWKS |
| console | 68 | trace-shape assertions; dog-fooded authz negative cases |
| portal | 100 (23 need Postgres) | RFC 6238 Appendix B vectors; queue claim/backoff/dead-letter; enumeration-safe reset flows |

### Integration tests

Three services keep a `make test-int` suite that runs against the real backend
instead of the in-process stand-in. Each is gated on an environment variable, so
the default `make test` stays dependency-free — while `make test-int` itself
sets `REQUIRE_TEST_*` and *fails* rather than skipping when the backend is
absent, which is the only way a gated suite keeps protecting anything.

idp and portal each ship **two** implementations of one storage interface —
in-memory (dev, and what the flow tests run against) and Postgres (production).
A single shared conformance suite runs against both, so the backends cannot
drift apart unnoticed. sessiond is shaped differently: one implementation, and a
fake backend (miniredis) that its default suite runs against. Its integration
suite is therefore not the same tests against a second backend but a distinct
set, covering only what a fake Redis cannot show.

| Project | Shape | Fast path | Real backend |
|---------|-------|-----------|--------------|
| idp | one suite, two backends (`internal/storage/storagetest`) | memory, every `go test` | Postgres, `TEST_DATABASE_URL` |
| portal | one suite, two backends (`server/test/contract/`) | memory, every `npm test` | Postgres, `TEST_DATABASE_URL` |
| sessiond | separate suites (`internal/store/integration_test.go`, tagged `integration`) | miniredis, every `go test` | Redis, `TEST_REDIS_URL` |

What real Redis buys that miniredis cannot: miniredis's Lua is gopher-lua, its
TTLs advance by `FastForward` rather than a clock, and its pub/sub is in-process
channels. sessiond's whole design is Lua scripts, sliding TTLs, and a revocation
broadcast, so all three matter. Atomicity is *not* on that list — miniredis
applies commands under a lock exactly as single-threaded Redis does, and the
concurrent-create cap tests in `concurrency_test.go` catch a non-atomic cap
without Docker. Nor is script execution: miniredis implements `EVAL`/`EVALSHA`.

idp and portal both define a `users` table, so give each its own database:

```sh
docker run -d --name meridian-pg-test -p 5433:5432 -e POSTGRES_PASSWORD=pw postgres:17
docker run -d --name meridian-redis-test -p 6380:6379 redis:7
docker exec meridian-pg-test sh -c 'until pg_isready -U postgres -q; do sleep 1; done'
docker exec meridian-pg-test createdb -U postgres idp_test
docker exec meridian-pg-test createdb -U postgres portal_test

(cd idp      && TEST_DATABASE_URL='postgres://postgres:pw@localhost:5433/idp_test?sslmode=disable' make test-int)
(cd portal   && TEST_DATABASE_URL='postgres://postgres:pw@localhost:5433/portal_test'              make test-int)
(cd sessiond && TEST_REDIS_URL='redis://localhost:6380/1'                                          make test-int)

docker rm -f meridian-pg-test meridian-redis-test   # schemas are applied by the suites; both are disposable
```

The sessiond suite `FLUSHDB`s between tests — point `TEST_REDIS_URL` at a
throwaway database, never a shared one.

CI runs all three against ephemeral `postgres:17` / `redis:7` services. Those
jobs also set `REQUIRE_TEST_DATABASE_URL=1` / `REQUIRE_TEST_REDIS_URL=1`, which
turns a missing backend into a red build rather than a suite that silently skips.

## Repo layout & docs map

```
keysmith/ idp/ sessiond/ sentinel/ bridge/ portal/ console/
  ├── README.md            what it is, why it's interesting, how to run it
  ├── THREAT_MODEL.md      assets, trust boundaries, abuse cases, residual risk
  ├── docs/adr/            one ADR per non-obvious decision
  └── Makefile             test / build / run / fmt / vet / check
platform/
  ├── terraform/           AWS (ECS Fargate) modules + envs/dev
  ├── compose/             local stack + smoke.sh
  └── docs/adr/            Fargate-over-EKS, SSM secrets + OIDC CI
docs/design/               the platform design doc
site/                      Astro portfolio site (/guide walkthrough)
scripts/dev-all.sh         everything in dev mode, no Docker
.github/workflows/         ci.yml (tests, gates), release.yml (images + deploy)
```

## Status

Not yet deployed: the Terraform for AWS is complete and reviewed but unapplied
(AWS credentials pending). Everything above runs locally today. The
[platform runbook](platform/README.md) documents the exact bring-up sequence for
when credentials exist.

## License

No license granted yet — this is a portfolio work; all rights reserved. Open an
issue if you want to use something from it.
