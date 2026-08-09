# KeySmith Threat Model

Scope: the keysmith service, its keystore file, and the trust relationships
with signer services (idp), verifiers (every other service), and operators.

## Assets

| Asset | Impact if compromised |
|-------|----------------------|
| Active private signing keys | Attacker mints arbitrary identities platform-wide — total compromise |
| KEK master key + keystore file | Same as above, offline |
| Signer API tokens | Attacker signs chosen claims (bounded by TTL cap and audit trail) |
| Admin API tokens | Attacker rotates in their own key or forces promotion |
| JWKS integrity | Attacker who can substitute the JWKS controls verification everywhere |

## Trust boundaries

1. **Public internet → JWKS endpoint.** Read-only, public keys only. Integrity
   relies on TLS in deployment (ALB/ACM); the document itself carries no secrets.
2. **Trusted services → sign/verify API.** Bearer tokens, constant-time
   hash comparison; per-class tokens (signer ≠ admin).
3. **Operators → admin API.** Separate token class; every mutation audited.
4. **Process → disk.** Envelope encryption (ADR 0002); AAD binds records to
   key identity; file mode 0600; atomic writes.

## Top abuse cases and mitigations

| # | Attack | Mitigation |
|---|--------|-----------|
| 1 | Forged token via `alg:none` / HS256 confusion / embedded `jwk` | Structurally impossible in the JOSE profile (ADR 0001); regression-tested per CVE class |
| 2 | Stolen keystore file | AES-256-GCM envelope; useless without KEK |
| 3 | Keystore record shuffling by attacker with file write | AAD mismatch → fails closed (tested) |
| 3b | Lifecycle rewrite by attacker with file write (retired key flipped back to `active`, `created_at` backdated past the dwell) | AAD covers state, all four timestamps and the document generation (v2). A v1 document — whose lifecycle fields are unauthenticated — is accepted on read and rewritten at v2 on that same start, so the deployed file self-upgrades with no operator step; a *retained* pre-upgrade copy is replayable with forged lifecycle state only where no generation anchor is configured (see 3c; residual risk below). The generation stops an authentic record kept from while the key was active being spliced over its retired successor (tested) |
| 3c | Whole-file rollback: an attacker with file write (or a bad restore) puts back an entire older keystore — internally consistent, opens cleanly, and in its v1 form carries forgeable lifecycle fields | Generation anchor (SSM parameter via `keystore.Anchor`, deployed by Terraform): the current generation is persisted outside the keystore after every write, and the store refuses to open a document below the anchored generation, *any* v1 document whenever an anchor is configured and has not been read as zero (a v1 generation is unauthenticated plaintext, so it is refused rather than compared), a zero-record document (this store never writes one, and with no records nothing authenticates its generation — otherwise an empty file substitutes for deletion and poisons the anchor), or a missing file the anchor knows was written. The anchor is seeded from the just-verified document at open, not only on write, so detection is live from the first anchored start rather than from the first rotation weeks later. It advances asynchronously, best-effort, strictly *after* the file is durable: a failed advance costs one write of detection lag and a loud error but never fails a durable write and never bricks a legitimate store. An anchor that cannot be read — or that holds a negative generation — opens an intact *v2* keystore degraded (loud error) and re-runs the check before the next advance, refusing to lower an anchor that records more writes than the store has seen (tested) |
| 4 | Signer-token holder mints long-lived tokens | `MaxTokenTTL` cap server-side; `exp`/`iat` are server-set, client-supplied values rejected |
| 5 | Token survives its key's retirement | `MaxTokenTTL ≤ RetireAfter` enforced at construction |
| 6 | Verifier cache poisoning window during rotation | `JWKSMaxAge ≤ PendingDwell/2` enforced; pending keys published before signing |
| 7 | Timing oracle on API token comparison | SHA-256 both sides + `subtle.ConstantTimeCompare`; uniform iteration over all configured tokens |
| 8 | Detailed verify errors as forgery oracle | `/v1/verify` returns coarse reasons only (`invalid`/`expired`/`not_yet_valid`) |
| 9 | Key material in logs / API responses | Key listing renders metadata views only; JWKS marshals public members only; private JWK serialization does not exist in the codebase; tested (`TestKeyListNeverLeaksPrivateMaterial`) |
| 10 | Panic → information leak | Recovery middleware returns opaque 500; details go to structured logs only |
| 11 | Confirmed compromise of an active private signing key | `POST /v1/keys/{id}/revoke` unpublishes it immediately and promotes a successor in the same call. Force-promotion is **not** the answer: it only stops the key signing new *legitimate* tokens, while the attacker holding the private half keeps minting for the full `RetireAfter` window |
| 12 | Two keysmith processes against one keystore file | Exclusive advisory lock (`<store>.lock`) held for the process lifetime; the second process fails to start rather than replaying a stale whole-document snapshot |

## Residual risks (accepted, documented)

- **LocalKEK master key lives in process memory and env/secret configuration.**
  Accepted for dev/single-node. Production: KMS-backed KEK (interface seam
  exists); memory-scraping adversaries are out of scope.
- **Whole-file rollback where no generation anchor is configured** (row 3c).
  Detection exists only when `KEYSMITH_GENERATION_ANCHOR` points at an SSM
  parameter; without it (dev, or any deployment that skips the wiring) the
  generation counter lives *in* the document and restoring an entire older file
  — including a retained v1 copy with rewritten lifecycle fields, which the
  upgrade-on-open would re-seal as valid v2 — is internally consistent and
  opens. The deployed Terraform wires the anchor unconditionally; the residual
  is the unanchored configuration itself, plus an adversary who can write both
  the keystore *and* the SSM parameter (that requires the task role or IAM
  access, a different compromise class than EFS file write). Two further
  windows are accepted with the anchor wired: the advance is best-effort after
  each durable write, so a write whose advance failed is unprotected until the
  next successful one; and an anchor that cannot be *read* at startup opens an
  existing **v2** keystore degraded — availability over fail-closed for the
  platform's only signer — with the check re-run before the next advance,
  which reports a rollback masked at open but does not stop the process
  serving it. A v1 document is *not* covered by that trade and is refused
  instead: accepting one degraded would take the forged lifecycle fields the
  v1 AAD leaves unauthenticated and launder them, since upgrade-on-open
  re-seals them as an authentic v2 record and destroys the evidence. The cost
  is the first-ever anchored start of a still-v1 store during an SSM outage. An
  adversary who can make the task's SSM reads fail sits in the IAM/network
  compromise class, not the file-write class. A fresh store is never
  initialized while the anchor is non-zero or unreadable; deliberate data
  replacement requires resetting the parameter to 0 (documented in
  Terraform). Gating v1
  acceptance on an operator-set variable was tried and removed: it did not
  close the window (nothing forces the variable back off) and it gave the
  upgrade deploy a way to brick the platform's only signer.
- **The v1 → v2 keystore upgrade is one-way.** keysmithd rewrites the store at
  v2 on the first start that reads a v1 document, and builds from before v2
  decode every record under the v1 AAD — so rolling the service's image tag back
  yields a signer that cannot open its own keystore. The EFS filesystem holding
  the store has no backup plan, so the only rollback is a copy of the keystore
  file taken off the access point *before* the upgrading task starts. Without
  one, recovery means deleting the file: every issued token and every cached
  JWKS entry is invalidated.
- **Single-writer file store.** No coordination for multi-node keysmith. The
  store now refuses to open if another process holds the lock, so the failure
  is loud instead of silent key loss — but it is a *startup* failure, and
  `/healthz` cannot see the condition it prevents. **Deployment requirement:**
  the ECS service must set `stop_before_start = true`; with the default
  start-before-stop rollout the replacement task cannot acquire the lock and
  the deploy fails while the old task keeps serving. Database store +
  rotation leader is future work.
- **Revocation reaches a verifier only when it can reach keysmith.** The client
  serves a stale key set through a keysmith outage on purpose (an unreachable
  key server must not take down every verifier), which means a revoked key
  keeps verifying there until the cache refreshes. The client warns once per
  outage and exposes `KeysAge()` so this degradation is alertable rather than
  silent; a hard staleness ceiling is a per-service availability choice and is
  deliberately not imposed here.
- **No HSM.** Software keys, accepted at this tier; the KEK interface is where
  an HSM/KMS integration would land.
- **Availability of the sign API** depends on this service; verifiers are
  insulated (local verification, stale-if-error JWKS cache in the client).
