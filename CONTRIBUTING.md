# Contributing / house style

Rules distilled from what the code actually does. Match them.

## Dependencies

- **Stdlib first.** Go services are `net/http` + `log/slog`; no web frameworks,
  no routers, no config libraries. Configuration is environment-only (12-factor),
  documented in the `cmd/*/main.go` doc comment.
- A dependency earns its place only when the stdlib genuinely can't
  (`pgx`, `go-redis`, `miniredis`, `argon2`). The Python compliance tooling is
  stdlib-only by contract — it must run on a bare auditor machine.
- Security-critical parsing is written here, not imported, when the imported
  surface is the risk (keysmith's `jose`, portal's TOTP). Each such choice has
  an ADR defending it.

## Tests

- `go test -race ./...` from any module, `npm test` in portal, and
  `python3 -m unittest discover tools/compliance` in sentinel must all pass
  **with no external services** — no Docker, no database, no network.
  In-memory implementations mirror production semantics exactly and are tested
  as contracts (portal's memory queue implements `SKIP LOCKED` claiming;
  sessiond tests run on miniredis).
- Integration tests against real infrastructure are opt-in behind
  `-tags integration` / `TEST_DATABASE_URL`, never the default.
- Table-driven tests; name the invariant, not the function. Test the security
  contract (timing uniformity, reuse detection, trace shape), not just the
  happy path. Known attack classes become permanent regression tests.

## Design & docs

- **One ADR per non-obvious decision** in `<project>/docs/adr/NNNN-title.md`.
  If a reviewer would ask "why not X?", the answer is an ADR, not a comment.
- **Every service ships a `THREAT_MODEL.md`**: assets, trust boundaries,
  abuse cases with mitigations, and honestly-stated residual risks.
- READMEs state what is wired versus what is a documented seam. Never claim an
  integration that isn't in the code.
- Content accuracy rule (applies to `site/` and READMEs alike): every claim
  must trace to code, an ADR, or a test run. No invented features or metrics.

## Code conventions

- `gofmt` clean (`make fmt` prints offenders); `go vet` clean; TypeScript is
  `strict` and must typecheck.
- Errors: fail closed. An unsafe configuration refuses to boot
  (keysmith validates its timing invariants at construction; sentinel refuses
  to start without a token).
- Auth comparisons are constant-time; secrets are stored hashed; dev-mode
  shortcuts log a loud `DEV MODE` warning and are impossible to enable
  implicitly.
- Every project Makefile supports the same verbs: `test`, `build`, `run`,
  `check`, plus `fmt`/`vet` for Go. The root Makefile fans out.

## Workflow

- Branch per task (`feat/...`, `fix/...`, `chore/...`); never commit to `main`.
- Conventional-commit subjects scoped by project: `feat(idp): ...`,
  `chore: gofmt`.
- Before pushing: `make check` at the root (vet + all tests + portal typecheck).
