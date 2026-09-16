# ADR 0004 — Phase 3 Relationship Trust & Pairing (DESIGN, RATIFIED)

- **Status:** **Accepted — RATIFIED (founder, 2026-09-16).** Design checkpoint:
  documentation only. **No Phase 3 implementation** (no migrations, routes,
  services, or client crypto) until a separate implementation phase begins.
- **Date:** 2026-09-16 (Revision 2 — security-review findings: Blockers 1–2,
  SAS/3DH clarification; ratified 2026-09-16)
- **Deciders:** Engineering (principal architect) — two product founders
- **Scope:** Relationship key hierarchy (statics, RK, SAS, sasProof, epochs),
  pairing state machine, device certificates, multi-device trust, recovery
  interaction (A–D), termination/re-key/revocation, server trust boundary,
  API/schema/DB proposal, ADR-0003 amendment (Phase-3 addendum).
- **Full design:** `docs/phase3/design-review.md` (§1–§12 + Revision Output 1–6
  - RATIFICATION RECORD).

## Context

Phase 0–2 delivered identity (Ed25519 via BIP39, ADR 0003), per-device key
material (ADR 0002), and untrusted-server E2EE (ADR 0001 D7). Revision 1
(`design-review.md` v1) surfaced a **contradiction**: RK was defined with
`transcriptDigest` in its salt while also claimed ephemeral-independent — if the
digest contained ephemerals, RK was NOT recomputable after device loss. It also
let "re-key + alerting" read as prevention of mnemonic compromise, and left SAS /
sasProof roles ambiguous. Revision 2 resolved all three; founders ratified
O1–O4 on 2026-09-16.

## Decisions

### D1. Key agreement — RK is static-static + epoch; ephemerals are transcript furniture

```
RK = HKDF-SHA512(
  ikm = X25519.scalarMult(RKA_priv, RKB_pub),   // static-static only
  salt = "enclave/relationship-rk-v1",          // domain separation
  info = "rk" ‖ 0x00 ‖ relationshipId ‖ 0x00 ‖ epoch ‖ 0x00 ‖ epochNonce,
  dkLen = 32)
```

- RK depends ONLY on: static-static DH, epoch/version material, domain
  separation (plus pair binding). The Revision-1 `transcriptDigest` salt term is
  deleted.
- **3DH ephemerals** (`EKA_pub`, `EKB_pub`) are exchanged and committed into the
  authenticated transcript T, but are **never key material**: they add
  liveness/freshness to the pairing event and provide the Phase-4 double-ratchet
  seam (ADR 0001 D14). Private ephemerals zeroized post-establishment (O4).
- **Consequence (RATIFIED O2):** RK is a long-lived per-epoch wrapping key (the
  ADR 0001 D5 KDK model). Recoverability does not require the partner online.
  **Phase 3 provides no forward secrecy for relationship content; Phase-4
  ratcheting is responsible for forward secrecy. The Phase-3 RK is NOT
  forward-secret and must not be described as such.**

### D2. Relationship statics — Model F (RATIFIED)

- **RATIFIED O1: Model F.** `RKA = HKDF-SHA512(seed, "enclave/relationship-identity-v1",
"x25519", 32)` → X25519 scalar. Every certified device re-derives it; no key
  transport; recovery works without the partner online (§8). Ratification
  introduces the ratified Phase-3 relationship identity derivation and therefore
  **supersedes the previous ADR 0003 wording that prohibited seed-derived
  material from the relationship layer** — see the ADR 0003 Phase-3 addendum
  (historical wording preserved and marked).
- **Alternative (NOT the MVP, retained for the record):** Model R — random
  per-pair static distributed via `W = HKDF(DH(src_priv,dst_pub),
"enclave/device-link-v1", "wrap")` + `E_W(RKA_priv)`, backed into the existing
  `enclave/recovery-wrap-v1` blob. No new primitive; one extra domain label. Full
  comparison in design review §5.4.

### D3. Pairing consent — three identity-signed steps over one canonical transcript

- States: PENDING → ACCEPTED → ESTABLISHED; terminals REJECTED / EXPIRED /
  CANCELLED / TERMINATED / MEMORIALIZED (U1).
- `T` = canonical byte-exact JSON (server-issued, zod-validated):
  `{t, relationshipId, epochNonce, epoch,
a{userId, identityPublicKey, relationshipStaticPublicKey, ephemeralPublicKey,
deviceCert{deviceId, devicePublicKey, keyVersion, certSignature}},
b{…same…}}`.
- Signed: offerConsent_A over `enclave/pairing-consent-v1` ‖ 0x00 ‖ **offerRecord**;
  acceptConsent_B and confirmConsent_A over the same prefix ‖ 0x00 ‖ **T**.
- ESTABLISHED requires: offerConsent_A + acceptConsent_B + confirmConsent_A +
  **both** sasProofs **present and equal**. M cannot reach ACCEPTED/ESTABLISHED
  alone (no identity privates, no RK).
- One active relationship per unordered pair (DB partial-unique); all
  transitions atomic, idempotent, terminal-sticky; offers single-use + TTL.

### D4. SAS vs sasProof (roles made exact)

- **SAS** = `HKDF(ikm=DH(RKA_priv,RKB_pub), salt="enclave/sas-v1", info="verify")`
  → display code. Authenticates: OOB human congruence that both apps used the
  same statics (same RK). **Never stored on the server** (a stored commitment
  is brute-forceable in 20 bits); compared in person / QR (U2). Independent of
  server relay and of ephemerals.
- **sasProof** = `HKDF(ikm=RK, salt="enclave/sas-proof-v1",
info=SHA-256(T), dkLen=16)`. It is **key confirmation AND transcript
  confirmation**: equal proofs prove same RK (key) AND same bytes of T —
  statics, ephemerals, certs, epoch — were used by both (transcript). Asserted
  only at ACCEPTED→ESTABLISHED; later devices join under the epoch via certs.
- **Server forgery:** impossible for consents (needs identity privates) and
  impossible for sasProofs (needs RK). The server can relay genuine artifacts,
  withhold them, or fail the request — never fabricate a passing artifact.

### D5. New domain labels (non-colliding with Phase 2)

`enclave/relationship-identity-v1`/`x25519`; `enclave/relationship-rk-v1`;
`enclave/sas-v1`/`verify`; `enclave/sas-proof-v1`; `enclave/device-link-v1`
(Model R only, not used in the ratified MVP); prefixes
`enclave/pairing-consent-v1`, `enclave/device-cert-v1`,
`enclave/pairing-transcript-v1` (T marker); envelope AAD prefix
`enclave/relationship-envelope-v1/<relationshipId>/<epoch>/…`. Non-collision
test-enforced.

### D6. Device certificates — identity-signed, mandatory for relationship participation

`enclave/device-cert-v1` ‖ 0x00 ‖ userId ‖ 0x00 ‖ deviceId ‖ 0x00 ‖
devicePublicKeyValue ‖ 0x00 ‖ keyVersion, signed Ed25519 by the user's identity
key. Server stores/validates structure; partner **clients** verify against the
partner's identityPublicKey before fan-out (T6/T7). Closes the account-secret
rogue-device gap.

### D7. Revocation — server-honored for MVP (RATIFIED O3)

- Server marks the device revoked, drops its recovery blob, invalidates its
  device secret, and **MUST refuse it new relationship/content operations** per
  this protocol. Partner clients exclude revoked devices on refresh.
- **Trust limitation (documented, not claimed away):** a malicious server can
  lie about revocation state, withhold revocation information, or refuse
  operations; a revoked/compromised device that already possesses valid keys may
  retain access to ciphertext/key material it already obtained; revocation does
  not retroactively erase secrets already held by a device. Client-verifiable
  signed revocation is deferred to Phase 4.

### D8. Forward secrecy stays deferred (ADR 0001 D14)

No ratchet in Phase 3; the 3DH ephemerals in T are the seam. Ratchet session
keys start from RK in Phase 4 (O2).

## Proposed (implementation-ready shape, approved for Phase-3 scope)

- P1. API surface: `POST/GET /v1/relationships`, `accept/confirm/establish/`
  `reject/cancel/rekey/terminate`, extended `POST /v1/devices` (cert fields).
  Error codes: `PAIRING_STATE_INVALID`, `PAIRING_ALREADY_ACTIVE`,
  `PAIRING_EXPIRED`, `PAIRING_REJECTED`, `DEVICE_CERT_MISSING`,
  `DEVICE_CERT_INVALID`, `RELATIONSHIP_TERMINATED`, `EPOCH_STALE`,
  `TOKEN_CONFLICT`, `TRANSCRIPT_MISMATCH`, `IDEMPOTENCY_REPLAY`. zod `.strict()`,
  standard envelope.
- P2. Tables: `relationships` (state, epoch, epochNonce, transcript, three
  consents, sasProof_A/B, statics), `relationship_epochs`; `devices` gains
  `certSignature`/`certVersion`; `encrypted_payloads` gains nullable
  `relationshipId`. Design only — no migration.
- P3. Active content migrates to relationship-scoped CK wraps; legacy
  device-key-sealed payloads remain under their original scope until re-sealed
  (U3).

## Ratified security decisions (O1–O4, 2026-09-16)

- **O1 — Model F.** RATIFIED. ADR 0003 amended (Phase-3 addendum); supersedes
  prior wording prohibiting seed-derived material in the relationship layer.
  Model R documented (§D2) but not the MVP.
- **O2 — Ephemeral exclusion from RK.** RATIFIED. Ephemerals stay in T + sasProof;
  MUST NOT become RK input. RK is a long-lived per-epoch wrapping key; Phase 3
  provides no forward secrecy; Phase-4 ratcheting owns forward secrecy; RK is not
  forward-secret.
- **O3 — Revocation.** RATIFIED (MVP server-honored). Server MUST prevent a
  revoked device from new relationship/content operations; limitations
  documented (D7 above).
- **O4 — Zeroization.** RATIFIED. Inherit Phase-2 zeroization (ADR 0003 §11) for
  mnemonic, seed, derived intermediates, ephemeral privates, and sensitive
  transient buffers wherever the environment permits. No new zeroization
  primitive.

## Open product decisions (unratified; not crypto-blocking)

- U1. Survivor/death model (Case D): MEMORIALIZED (recommended) vs estate delegation.
- U2. SAS UX: 6-digit / 4-digit+2-emoji / QR-scan-in-person (QR-first).
- U3. Re-key/re-seal migration budget: gradual vs backfill.
- U4. Re-key/rotation alerting into the ADR 0003 §9 alerting roadmap
  (containment, not prevention).

## Consequences

### Positive

- The ephemeral/RK contradiction is closed: RK is provably recomputable from
  statics + epoch (recovery-safe), while sasProof still authenticates the full
  transcript including ephemerals.
- State machine is cryptographically airtight: three signed consents +
  unforgeable equal-proof establishment; server can relay/withhold/fail but not
  forge.
- SAS is off the server entirely (no brute-forceable commitment).
- Ratification of O1 records the intentional Model F seed use; ADR 0003's
  Phase-3 addendum preserves and marks the superseded wording rather than
  silently rewriting history.
- Server-honored revocation's trust limits and T8's containment-only posture are
  documented rather than over-claimed.

### Accepted trade-offs

- RK is a long-lived per-epoch wrapping key (no FS until Phase-4 ratchet) — the
  explicit cost of no-transport recovery.
- T8 (mnemonic + server ⇒ relationship content) is unavoidable given
  server-stored recovery material + seed-derived identity; re-key + alerting are
  containment only.
- Server-honored revocation is not cryptographically truthful under a malicious
  server — accepted for MVP, client-verified revocation in Phase 4.

## Status

**Accepted — RATIFIED** (2026-09-16). No Phase 3 production implementation
exists: no migrations, routes, services, or client crypto. Blocking nothing;
remaining open items are the OPEN PRODUCT DECISIONS U1–U4 (not crypto-blocking).
ADR 0003 is amended by its Phase-3 addendum. ADR 0001/0002 are unchanged.
