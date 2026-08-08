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
| 3b | Lifecycle rewrite by attacker with file write (retired key flipped back to `active`, `created_at` backdated past the dwell) | AAD covers state, all four timestamps and the document generation (v2). A v1 document — whose lifecycle fields are unauthenticated — is accepted on read and rewritten at v2 on that same start, so the deployed file self-upgrades with no operator step; a *retained* pre-upgrade copy stays replayable with forged lifecycle state until the document version is anchored outside the keystore (residual risk below). The generation stops an authentic record kept from while the key was active being spliced over its retired successor (tested) |
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
- **Whole-file rollback of the keystore, including downgrade to version 1.** The
  generation counter that binds a record to a particular write lives *in* the
  document, so restoring an entire older file (record set plus its generation) is
  internally consistent and opens. A version 1 document is the stronger form of
  the same attack: its lifecycle fields sit outside the AEAD, so a retained
  pre-upgrade copy can be replayed with `state` and the timestamps rewritten, and
  the upgrade-on-open would then re-seal the forged lifecycle as a valid v2
  record. Both need the same fix — an anchor outside the keystore (current
  generation and minimum document version in an SSM parameter, or the KMS
  encryption context once the KMS KEK lands) and a refusal to open below it.
  Gating v1 acceptance on an operator-set variable was tried and removed: it did
  not close the window (nothing forces the variable back off) and it gave the
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
