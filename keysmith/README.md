# KeySmith — Key Management & JWT Signing

Cryptographic key lifecycle as a service: zero-downtime signing-key rotation, a
hardened minimal JOSE implementation, envelope-encrypted key storage, and a
JWKS endpoint engineered so that verifier caches can never go stale at the
wrong moment.

Every other Meridian service either asks KeySmith to sign (idp) or verifies
locally against its JWKS (everyone else).

## Why this project is interesting

1. **Rotation as a state machine with enforced timing invariants.** Keys move
   `pending → active → retiring → retired`. A new key is *published before it
   ever signs* (the pending dwell), and a demoted key *stays published until
   every token it signed has expired*. The two invariants that make this
   airtight — `JWKS max-age ≤ dwell/2` and `max token TTL ≤ retire window` —
   are validated at service construction: an unsafe configuration fails to
   boot rather than failing at 3am. See [ADR 0003](docs/adr/0003-rotation-state-machine.md).

2. **A JOSE layer where historical JWT CVEs are structurally impossible.**
   Allowlist of three asymmetric algorithms, no HMAC, no `none`, no
   token-controlled algorithm choice, no `jwk`/`jku`/`x5u`/`crit`, unknown
   header parameters rejected. Each CVE class is a permanent regression test.
   See [ADR 0001](docs/adr/0001-minimal-jose-implementation.md) for why this
   beats importing a general-purpose library here.

3. **Envelope encryption with a KMS-shaped seam.** Per-key DEKs under a
   wrap/unwrap KEK interface; GCM AAD binds ciphertexts to key identity *and
   lifecycle position*, so neither a record-shuffling attacker nor one editing
   the plaintext state field gets key confusion or a resurrected retired key —
   they get integrity failures. See [ADR 0002](docs/adr/0002-envelope-encryption.md).

## Layout

```
jose/       JWS sign/verify, JWT claims, JWK/JWKS — zero external deps
keystore/   lifecycle manager, envelope encryption, memory + encrypted-file stores
service/    HTTP API: sign, verify, JWKS, admin rotation
client/     Go client: remote signing, local verification, stale-tolerant JWKS cache
cmd/keysmithd/  the daemon
```

## API

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /.well-known/jwks.json` | public | Published verification keys; `Cache-Control` + `ETag` |
| `GET /healthz` | public | Healthy ⇔ an active signing key exists |
| `POST /v1/sign` | signer token | Sign claims; `exp`/`iat` are server-set, TTL capped |
| `POST /v1/verify` | signer token | Convenience verification (coarse failure reasons) |
| `GET /v1/keys` | admin token | Key metadata (never private material) |
| `POST /v1/keys/generate` | admin token | Create a pending key |
| `POST /v1/keys/{id}/promote` | admin token | Promote (dwell-gated; `force` for an urgent scheduled rotation) |
| `POST /v1/keys/{id}/revoke` | admin token | Compromise response: unpublish now and promote a successor; `reason` required and audited |

## Run it

```sh
# Dev mode: ephemeral in-memory keys
KEYSMITH_DEV_MODE=1 KEYSMITH_SIGNER_TOKENS=dev-signer KEYSMITH_ADMIN_TOKENS=dev-admin \
  go run ./cmd/keysmithd

# Production shape: encrypted file store
KEYSMITH_MASTER_KEY=$(head -c32 /dev/urandom | base64) \
KEYSMITH_SIGNER_TOKENS=... KEYSMITH_ADMIN_TOKENS=... \
  go run ./cmd/keysmithd
```

Configuration is environment-only; the full variable list is documented in
[`cmd/keysmithd/main.go`](cmd/keysmithd/main.go).

## Tests

```sh
make test    # go test -race ./...
make bench   # sign/verify benchmarks across EdDSA / ES256 / RS256
```

Coverage highlights: every historical JOSE attack class
(`jose: TestKnownAttackPatterns`), full rotation lifecycle against a fake
clock, signing across a rotation boundary, restart mid-rotation on the
encrypted store, concurrent signing during rotation under `-race`, KEK
mismatch and ciphertext-shuffling tamper cases, timing-safe auth boundaries.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md) — assets, trust boundaries, ten abuse
cases with mitigations, and the residual risks accepted at this deployment tier.
