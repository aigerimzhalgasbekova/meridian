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
| 4 | Signer-token holder mints long-lived tokens | `MaxTokenTTL` cap server-side; `exp`/`iat` are server-set, client-supplied values rejected |
| 5 | Token survives its key's retirement | `MaxTokenTTL ≤ RetireAfter` enforced at construction |
| 6 | Verifier cache poisoning window during rotation | `JWKSMaxAge ≤ PendingDwell/2` enforced; pending keys published before signing |
| 7 | Timing oracle on API token comparison | SHA-256 both sides + `subtle.ConstantTimeCompare`; uniform iteration over all configured tokens |
| 8 | Detailed verify errors as forgery oracle | `/v1/verify` returns coarse reasons only (`invalid`/`expired`/`not_yet_valid`) |
| 9 | Key material in logs / API responses | Key listing renders metadata views only; JWKS marshals public members only; private JWK serialization does not exist in the codebase; tested (`TestKeyListNeverLeaksPrivateMaterial`) |
| 10 | Panic → information leak | Recovery middleware returns opaque 500; details go to structured logs only |

## Residual risks (accepted, documented)

- **LocalKEK master key lives in process memory and env/secret configuration.**
  Accepted for dev/single-node. Production: KMS-backed KEK (interface seam
  exists); memory-scraping adversaries are out of scope.
- **Single-writer file store.** No coordination for multi-node keysmith;
  deploying >1 replica against one file is a documented misconfiguration
  (health check + docs). Database store + rotation leader is future work.
- **No HSM.** Software keys, accepted at this tier; the KEK interface is where
  an HSM/KMS integration would land.
- **Availability of the sign API** depends on this service; verifiers are
  insulated (local verification, stale-if-error JWKS cache in the client).
