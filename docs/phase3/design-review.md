# Phase 3 — Relationship Trust & Pairing: DESIGN REVIEW (Revision 2, RATIFIED)

- **Status:** RATIFIED (founder, 2026-09-16) — security decisions O1–O4 accepted;
  ADR 0004 is the ratified decision record and ADR 0003 is amended (Phase-3
  addendum). **No Phase 3 implementation:** no migrations, no routes, no client
  crypto. This checkpoint commits documentation only.
- **Date:** 2026-09-16 (Revision 2 — security-review findings, Blockers 1–2,
  SAS/3DH; ratified 2026-09-16)
- **Authored by:** Engineering (principal architect) — for the two product founders.
- **Accompanying record:** `docs/adr/0004-phase3-relationship-trust-pairing.md`
  (ratified checkpoint).
- **Companion ADRs:** ADR 0001 (architecture, trust model, key hierarchy, D14),
  ADR 0002 (payload protocol, AAD), ADR 0003 (identity/recovery, key separation;
  amended by the Phase-3 addendum).

> This document ends with the twelve mandated review sections (§1–§12), followed
> by the **Revision Output** mandated in the security review (six numbered items)
> and the **Ratification Record**. Security decisions O1–O4 are RATIFIED. The
> only remaining open items are the OPEN PRODUCT DECISIONS U1–U4, which do not
> block the ratified cryptographic/state-machine design.

---

## 1. Objective

Design the cryptographic and state-machine layer that lets exactly two users
(ADR 0001 D6) establish a **trusted relationship** over an untrusted server:
how pairing is consented to, how a recoverable **relationship root key (RK)** is
derived without key transport, how each user's devices are bound to their
identity so the partner can trust them, how the relationship interoperates with
Phase 2 recovery, and how it terminates. Deliverable is a ratified design; **no
code is produced in this phase.**

Preserved non-negotiables (Phases 0–2, unchanged):

- Server is an **untrusted coordinator** (ADR 0001 D7). It relays ciphertext and
  signed metadata; it must never learn a private scalar, RK, a content key, a
  SAS value, or plaintext.
- Identity is anchored ONLY by the user's **Ed25519 identity signing key**
  (ADR 0003 §1). "Server says X is Bob's key" is never proof; only an Ed25519
  signature binds key material to an identity.
- Seed-derived material never encrypts content (ADR 0003 §5, as amended by the
  Phase-3 addendum). Seed-derived keys sign and feed ECDH inputs (Model F,
  RATIFIED O1); content keys are random.
- Audited primitives only; **no custom cryptography** (ADR 0001 D4, D6). No
  algorithm negotiation; version literals pinned in contracts.
- Cross-runtime parity: TypeScript reference (noble) and Dart core
  (`cryptography`) mirror byte-for-byte, with committed deterministic vectors
  in `packages/contracts/test-vectors/` (ADR 0002 D3).
- Cryptography bound by the AAD/domain convention:
  `UTF-8("enclave/<domain>-v1/" + keyRef)`, RFC 4648 base64,
  `ciphertext ‖ 16-byte poly1305 tag`, zod `.strict()`, envelope
  `{ok:true,data}` / `{ok:false,error:{code,message}}`.

## 2. Scope — In / Out

**In (designed, not implemented):**

- Key hierarchy additions: relationship static keys, RK, SAS, sasProof, epochs,
  domain labels.
- Pairing state machine and its signed consent/confirmation protocol.
- Device trust: identity-signed device certificates, multi-device model.
- Recovery interaction (cases A–D) and termination/re-key/revocation.
- Server trust-boundary table; proposed API surface (zod + envelope), new error
  codes, proposed DB tables/columns.
- Test strategy (pairing, key derivation, multi-device, recovery, security) and
  TS↔Dart interop vector plan.

**Out (explicitly NOT designed here; cross-references):**

- **Double ratchet / per-message forward secrecy** — deferred by ADR 0001 D14.
  This design reserves the seam; Phase-4 ratchets will build per-device-pair
  session ratchets on top of the canonical RK (§5.6).
- Payload envelope layout beyond the Phase-1/2 convention (§5.5 relationship-
  scoped content-key wrapping).
- Push, notifications, media pipeline, UI/UX flows, reputation/reporting.
- Identity-signed client-verifiable device-revocation lists — deferred (O3).
- Any Cloudflare/infra work.

## 3. Security Model (inherited constraints)

| Constraint                                                              | Enforced by                                                        |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Identity anchored only by Ed25519 signature over a single-use challenge | ADR 0003 §2; `verifyEd25519` (node:crypto JWK)                     |
| Identity/device/relationship/content keys are separate layers           | ADR 0003 §6 + Revision 2 §5.4; rules below                         |
| Server stores no private material; blobs opaque                         | ADR 0002 D1/D3; repository boundaries                              |
| Devices are independently random, never seed-derived                    | ADR 0003 §4                                                        |
| Payload ownership + device checks enforced on every route               | `requirePrincipal`, ownership checks                               |
| Cross-language byte parity                                              | reference-client/reference-recovery ↔ dart_core, committed vectors |

Layer-separation rules (this design, restated for review):

1. Seed → only: identity signing key (Ed25519), recovery wrapping key, and —
   **Model F relationship static X25519 scalar (RATIFIED O1)** (ADR 0003
   Phase-3 addendum, §5.7).
2. ECDH output (DH between relationship statics) → only RK + SAS. RK wraps
   _keys_, never content. SAS is OOB-only, never transmitted.
3. Content keys: fresh random per drop (ADR 0001 D5), wrapped under RK.
4. A seed compromise must never yield content directly (ADR 0003 §5 matrix
   stays true; T8 revision in §4/§12 keeps it a documented catastrophic case,
   re-key being post-detection containment only).

## 4. Threat Model (T1–T18)

Notation: **M** = malicious server; **E** = external network attacker;
**Pc** = compromised device of user A; **S** = stolen mnemonic; **P** = partner's
device. Terminology: a server can **relay** genuine artifacts, **withhold** them
(availability), or **fail** a request; it can **forge** only if it can compute a
passing artifact it does not already possess. This distinction is used below and
in §5.3.

| #   | Threat                                                                                                | Blast radius                                                                     | Mitigation (this design)                                                                                                                                                                                                                                                                                                                                                                                     | Status                                                                                                                                               |
| --- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1  | M substitutes A's or B's relationship static pubkey during pairing (silent MITM on the key agreement) | whole relationship secrecy                                                       | Statics are **identity-signed into the transcript**; sasProof equality (both derived from the real RK) fails on any substitution; SAS compared OOB as the human layer                                                                                                                                                                                                                                        | ACK'd                                                                                                                                                |
| T2  | M forges pairing consent (pairs two accounts without either user)                                     | account integrity                                                                | Consent = identity Ed25519 signatures M cannot compute; M can relay only                                                                                                                                                                                                                                                                                                                                     | Closed                                                                                                                                               |
| T3  | M substitutes content envelopes / per-drop wrapped keys                                               | per-drop integrity                                                               | XChaCha20-Poly1305 under RK-derived/device keys; AAD binds relationship+epoch+keyRef                                                                                                                                                                                                                                                                                                                         | ACK'd                                                                                                                                                |
| T4  | M replays a stale relationship envelope or an old establishment                                       | replay of drop                                                                   | Nonce+AAD binding; monotonic envelope id; one-shot establishment (single-use transcript); clients reject duplicates                                                                                                                                                                                                                                                                                          | Closed                                                                                                                                               |
| T5  | M learns RK or a content key from stored data                                                         | —                                                                                | RK computed by ECDH on-device; never transmitted; server stores only statics, signatures, transcript, sasProofs, ciphertext                                                                                                                                                                                                                                                                                  | Closed                                                                                                                                               |
| T6  | M registers a rogue device under B's account to receive relationship material                         | partner's content leaked to attacker                                             | Device certs identity-signed; partner clients fan out ONLY to certified devices; certs verified against B's identityPublicKey (§7)                                                                                                                                                                                                                                                                           | Closed                                                                                                                                               |
| T7  | Rogue device created by account-secret thief, pre-cert                                                | content of A/B                                                                   | Certificate flow mandatory for relationship participation (DEVICE_CERT_MISSING); account-secret-only devices cannot join a relationship                                                                                                                                                                                                                                                                      | Closed w/ migration note                                                                                                                             |
| T8  | S (stolen/copied mnemonic) → attacker derives relationship material                                   | relationship content, both models                                                | **Catastrophic self-custody case (ADR 0003 §9). NOT preventable by any design that keeps server-aided recovery.** Re-key + alerting are **post-detection containment**, not prevention. Model F: attacker needs server relay for B's statics/epoch — with server access, RK derivable. Model R: attacker additionally needs the wrapped static blob to exist. Full analysis: §5.4 and Revision Output item 4 | **ACCEPTED (RATIFIED O1):** prevention impossible for any design keeping server-aided recovery + seed identity; containment = re-key + alerting (U4) |
| T9  | Replaying a pairing offer to exhaust/poison state                                                     | availability                                                                     | single-use challenge + TTL on offers; one active relationship per pair (DB partial-unique)                                                                                                                                                                                                                                                                                                                   | Closed                                                                                                                                               |
| T10 | M races/corrupts state transitions (e.g., ESTABLISHED before both consent)                            | state integrity                                                                  | atomic DB transitions; ESTABLISHED requires offer+accept+confirm consents AND equal sasProofs                                                                                                                                                                                                                                                                                                                | Closed                                                                                                                                               |
| T11 | M learns the relationships graph (A is paired with B)                                                 | relationship-graph privacy                                                       | Accepted operational metadata (ADR 0001 D7) — presence is not content                                                                                                                                                                                                                                                                                                                                        | ACK'd                                                                                                                                                |
| T12 | P sends a bogus device cert                                                                           | partner trust                                                                    | Cert verified client-side against partner's identityPublicKey; server also validates Ed25519 structure                                                                                                                                                                                                                                                                                                       | Closed                                                                                                                                               |
| T13 | Offline re-ordering of signed transitions (ACCEPT after REJECT)                                       | state integrity                                                                  | monotonic state machine + per-transition idempotency; terminal states are sticky                                                                                                                                                                                                                                                                                                                             | Closed                                                                                                                                               |
| T14 | Epoch/key-version confusion (old key reused after re-key)                                             | residual content                                                                 | RK binds relationshipId+epoch; zod literals pin alg/version; no negotiation                                                                                                                                                                                                                                                                                                                                  | Closed                                                                                                                                               |
| T15 | Revoked device of B keeps receiving new envelopes until server acts                                   | post-revocation content                                                          | Server revokes cert+device (`revokedAt`); partner clients exclude on refresh. **RATIFIED O3 (MVP):** server MUST refuse the revoked device new operations; malicious-server limitation documented (§5.7); client-verified revocation list deferred to Phase 4                                                                                                                                                | MVP-ACCEPTED (limitations documented)                                                                                                                |
| T16 | Algorithm confusion / cipher downgrade                                                                | keys on wire                                                                     | Fixed constants: X25519, Ed25519, HKDF-SHA512, XChaCha20-Poly1305 (zod literals); no negotiation                                                                                                                                                                                                                                                                                                             | Closed                                                                                                                                               |
| T17 | Local secure-storage theft of a live device                                                           | that device's keys **and** the user's RK (both F and R; device holds the static) | Out of scope (host compromise); cert revocation bounds ongoing exposure; per-drop random keys bound retrospective scope                                                                                                                                                                                                                                                                                      | ACK'd                                                                                                                                                |
| T18 | Supply chain (noble/`cryptography`)                                                                   | keys                                                                             | Pinned audited libs, as Phases 1–2; dependency-review in CI (Phase 4+)                                                                                                                                                                                                                                                                                                                                       | ACK'd                                                                                                                                                |

## 5. Cryptographic Design

### 5.1 Primitives (no new libraries, no ECIES/custom crypto)

| Primitive          | Use                                                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| X25519             | relationship static ECDH; establishment ephemeral publics (transcript-only, §5.3); Model R device-link wrap (domain `enclave/device-link-v1`) |
| Ed25519            | identity signatures (offer/accept/confirm consents, device certs)                                                                             |
| XChaCha20-Poly1305 | relationship/key and content envelopes (existing)                                                                                             |
| HKDF-SHA512        | all new derivations (relationship identity, RK, SAS, sasProof, Model R device link) — same convention as ADR 0003                             |
| CSPRNG             | ephemerals, epochNonce, per-drop content keys                                                                                                 |

### 5.2 Key hierarchy (Model F base case)

```
BIP39 seed
├─ identity signing key (Ed25519)                    [ADR 0003, unchanged]
├─ recovery wrapping key                             [ADR 0003, unchanged]
└─ relationship static key RKA (X25519)              [NEW: HKDF below — Model F]
       │  X25519(RKA_priv, RKB_pub) == X25519(RKB_priv, RKA_pub)
       ├──────────────────────────────┬──────────────┴───────────────┐
       ▼                              ▼                              ▼
   RK (relationship root key)    SAS (OOB verification)      esROOT (reserved for
   wraps per-drop content key                               Phase-4 double ratchet;
   only — never content                                     D14 seam, §5.6)
```

New HKDF-SHA512 domains (all distinct from Phase 2 labels; **canonical RK binds
NO ephemeral material** — see formula at Revision Output item 1):

| Domain                             | salt                                                            | info         | Output                                                               | Produces |
| ---------------------------------- | --------------------------------------------------------------- | ------------ | -------------------------------------------------------------------- | -------- |
| `enclave/relationship-identity-v1` | `x25519`                                                        | 32 bytes     | RKA / RKB private scalar (§5.3)                                      |
| `enclave/relationship-rk-v1`       | `rk` ‖ 0x00 ‖ relationshipId ‖ 0x00 ‖ epoch ‖ 0x00 ‖ epochNonce | 32 bytes     | **RK** (REVISION: no transcript digest)                              |
| `enclave/sas-v1`                   | `verify`                                                        | 20 bits→code | SAS (6-digit / 4-digit+2-emoji / QR) — client/OOB only, NEVER stored |
| `enclave/sas-proof-v1`             | `SHA-256(T)` (transcript digest)                                | 16 bytes     | sasProof commitment (key + transcript confirmation)                  |
| `enclave/device-link-v1`           | `wrap`                                                          | 32 bytes     | Model R only: per-device transport wrap key W                        |

Message prefixes (prefix + `0x00`-separated fields, same pattern as
`enclave/recovery-v1`):

- `enclave/pairing-consent-v1` — identity-signed offer / accept / confirm consents
- `enclave/device-cert-v1` — identity-signed device certificate
- `enclave/pairing-establish-v1` — reserved (Phase-4 ratchet handshake marker)

Envelope AAD prefix for relationship-scoped content key wraps:
`enclave/relationship-envelope-v1/<relationshipId>/<epoch>/…`.

### 5.3 Exact keys, transcripts, and what each artifact authenticates

**Relationship static scalar (Model F):**
`RKA_priv = HKDF-SHA512(ikm=seed, salt="enclave/relationship-identity-v1", info="x25519", dkLen=32)`.
The 32-byte output is the X25519 private key seed; `pub = X25519.publicKey(priv)`
(RFC 7748, clamping in scalar mult, identical in noble and Dart `cryptography`;
interop vector required, §11). Recomputable from the mnemonic, giving trivially
recoverable relationship continuity (§8) — the whole point of Model F.

**Establishment ephemerals.** Each pole generates fresh
`EKA_priv/EKA_pub` (resp. EKB) X25519 keypairs at pairing time. The private
halves are **not key material** — they are used for nothing but being present in
the transcript (liveness/freshness of the pairing event; the Phase-4 ratchet
seam, §5.6). Private halves are zeroized after establishment (RATIFIED O4).

**Transcript T.** The server assembles ONE canonical transcript and returns its
exact bytes to both clients; every signature and the sasProof digest are over
those bytes, so both poles commit to a byte-identical view:

```
T = canonical UTF-8 JSON (zod-validated, server-issued, byte-exact):
{
  "t": "enclave/pairing-transcript-v1",
  "relationshipId": <uuid>,
  "epochNonce": <b64, 16 bytes, initiator-issued in the offer record; binds RK>,
  "epoch": 1,
  "a": { "userId", "identityPublicKey",
         "relationshipStaticPublicKey": RKA_pub,
         "ephemeralPublicKey": EKA_pub,
         "deviceCert": { "deviceId", "devicePublicKey", "keyVersion", "certSignature" } },
  "b": { "userId", "identityPublicKey",
         "relationshipStaticPublicKey": RKB_pub,
         "ephemeralPublicKey": EKB_pub,
         "deviceCert": { "deviceId", "devicePublicKey", "keyVersion", "certSignature" } }
}
```

**Exact fields — who signs / commits / sees what:**

| Artifact                | Computed over                                                                                             | Who computes            | Server-stored?                   | Server can forge?                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| offerConsent_A          | `enclave/pairing-consent-v1` ‖ 0x00 ‖ offerRecord (relationshipId, epochNonce, a-fields, b=identity only) | client A (Ed25519)      | yes                              | No (needs A's identity private)                                                                           |
| acceptConsent_B         | `enclave/pairing-consent-v1` ‖ 0x00 ‖ T                                                                   | client B (Ed25519)      | yes                              | No                                                                                                        |
| confirmConsent_A        | `enclave/pairing-consent-v1` ‖ 0x00 ‖ T                                                                   | client A (Ed25519)      | yes                              | No                                                                                                        |
| sasProof_A / sasProof_B | `HKDF(ikm=RK, salt="enclave/sas-proof-v1", info=SHA-256(T), dkLen=16)`                                    | client A / B (needs RK) | yes (compared for equality only) | No (needs RK = DH privates); can relay genuine proofs, withhold, or only _report_ equality of what it has |
| SAS                     | `HKDF(ikm=DH(RKA_priv,RKB_pub), salt="enclave/sas-v1", info="verify")` → code                             | client A / B            | **never**                        | No (needs RK); cannot read, see, or influence the OOB comparison                                          |

**Definitions (preferred over the old wording "3DH proof"):**

- **What SAS authenticates:** the human, out-of-band congruence check that both
  poles' apps actually used the same statics — the RK both derived is the same
  and the key exchange was not MITM'd. SAS depends only on the static DH (same
  ikm as RK), so it is independent of the server-relayed ephemerals and of any
  relay behavior. Compared in person (so the two people are the channel).
- **What sasProof authenticates:** **key confirmation AND transcript
  confirmation.** Because `ikm=RK`, equality of sasProof_A and sasProof_B proves
  both poles derived the same RK (key confirmation). Because `info=SHA-256(T)`,
  equality additionally proves both poles derived RK from the same transcript —
  statics, ephemerals, certs, epochNonce, relationshipId — all byte-identical
  (transcript confirmation). If M substitutes any ephemeral or static for one
  pole only, the two proofs differ → ESTABLISHED fails → REJECTED. It is a
  **one-shot artifact**: asserted only at the ACCEPTED→ESTABLISHED transition;
  later-joining devices join under the epoch via certs and never re-assert.
- **Server forgery:** neither consent signature nor either sasProof can be
  forged by M (needs identity privates / RK). M can only relay genuine
  artifacts, withhold them, or fail the request. This is stated explicitly for
  T10 and in the trust-boundary table (§10.1).

**Why ephemerals stay out of RK (BLOCKER 1 resolution).** RK depends ONLY on:
static-static DH, epoch/version material (epoch + epochNonce), and domain
separation (salt, plus relationshipId for pair binding). Ephemerals are
authenticated furniture of T. Security consequence, stated plainly:

- **Positive:** any certified device (including a recovered one) recomputes RK
  from statics + epoch, with no key transport — the recovery guarantee that
  static-static was chosen for. Ephemeral substitution by M cannot perturb RK
  (it is not in the key), and sasProof equality still catches the substitution
  on the transcript side.
- **Negative:** canonical RK is a **long-lived wrapping key per epoch**, not a
  forward-secret session key. Compromise of any device holding RKA_priv (T17)
  exposes the epoch's RK to decrypt all epoch content wrapped under it; per-drop
  random content keys bound the _retrospective_ scope but there is no per-message
  FS. This is precisely the ADR 0001 D14 deferral, unchanged; the Phase-4 double
  ratchet (which derives per-device-pair session keys that DO provide FS) builds
  on top of RK without altering its derivation.

### 5.4 Model F vs Model R — full comparison (BLOCKER 2)

| Criterion                       | Model F — seed-derived static                                                                           | Model R — random static                                                                                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Derivation                      | `RKA = HKDF(seed, relationship-identity-v1, x25519)`                                                    | `RKA = CSPRNG(32)` at pairing; no seed trace                                                                                                                                          |
| Distribution                    | none — every device re-derives                                                                          | device-link wrap `W=HKDF(DH(src_priv,dst_pub), device-link-v1, wrap)` then `E_W(RKA_priv)`; **plus** backup into existing `enclave/recovery-wrap-v1` blob (or skip = weaker recovery) |
| Mnemonic compromise (no server) | attacker gets RKA but not B's statics → RK not derivable; content safe                                  | attacker gets nothing; content safe                                                                                                                                                   |
| Mnemonic + server (T8)          | RKA re-derived; B's statics + epoch relayed by server → **RK fully derivable, no user action required** | RK requires the user's RKA **recovery blob** to exist on server (unwrap with seed-derived wrap key) → derivable **if that backup was taken**                                          |
| Server compromise               | statics/signatures/ciphertext only; no decryption (same as Models)                                      | identical                                                                                                                                                                             |
| Device compromise               | device holds RKA_priv → epoch RK exposed                                                                | identical (device holds RKA_priv after unwrap)                                                                                                                                        |
| Full device loss                | automatic: re-derive from mnemonic                                                                      | if blob backed up: automatic; if not: **requires partner online to re-establish**                                                                                                     |
| Recovery without partner        | always works                                                                                            | conditional (blob-backed)                                                                                                                                                             |
| Key transport complexity        | none                                                                                                    | device-link wraps + recovery blob write path (new domain `enclave/device-link-v1`, no new primitive)                                                                                  |
| Revocation                      | epoch rotation + device revocation; compromised static ⇒ epoch++ with new statics                       | identical                                                                                                                                                                             |
| Relationship continuity         | trivial (any device, any era)                                                                           | needs distribution machinery or re-establish                                                                                                                                          |
| Blast radius                    | whole-epoch RK if (mnemonic + server) or device compromise                                              | whole-epoch RK if (mnemonic + server + shipped blob) or device compromise                                                                                                             |

**Net, honestly stated:** Model R does **not** eliminate T8 — since RK must be
recoverable, the wrapped static exists server-side and the seed-derived wrap key
unlocks it; mnemonic + server defeats confidentiality in both models (this is
the ADR 0003 §5 "mnemonic + blob" row, unchanged). Model R's only real delta is
making that catastrophic outcome **conditional on a user backup having been
taken** (a knob users can turn off only by giving up device-loss recovery). Model
F's delta is the ergonomic certainty of recovery and zero transport machinery.
**No design can make recovery-without-partner and mnemonic-compromise-resistance
simultaneously perfect on a server that stores recovery material; the product
must choose the trade the ADRs already made (recovery is first-class, self-custody
is documented).**

### 5.5 RK → content key wrapping (relationship scope)

Phase-1/2 payloads are sealed under a _device_ sealing key (single device reads).
Phase 3 moves active content to **relationship scope**: per drop, fresh random
`CK` sealed under RK (`E_RK(CK)`), drop ciphertext sealed under `CK` (ADR 0001
D5). Any certified device of either user (including a recovered device that
recomputed RK) can open it. Legacy device-key-sealed payloads remain readable by
the original device until re-sealed (ADR 0003 §8 pattern) — OPEN PRODUCT U3.

### 5.6 Forward secrecy / ratchet seam (unchanged by the revision)

The handshake already exchanges 3DH ephemerals into the authenticated transcript.
Canonical RK stays deterministic from statics+epoch so that every device and
recovery re-derives it — the MVP requirement. Phase-4 double ratchet (ADR 0001
D14) will start from RK and produce per-device-pair session keys with fresh
ephemerals and their own DH ratchets; that is where per-message forward secrecy
lands, and it needs no change to RK's derivation. Whether the ephemerals also
fold into a _per-establishment_ root (O2 predecessor) is now scope-locked to that
Phase: folding them in today would break trivial recovery, which the product
requires. **The Phase-3 RK is NOT forward-secret; do not describe it as such.**

### 5.7 Ratified security posture (O1–O4, 2026-09-16)

Founder ratification pins these properties; they are non-negotiable for any
Phase-3 implementation:

1. **O1 — Model F.** The relationship static X25519 key is seed-recomputable
   (`enclave/relationship-identity-v1`/`x25519`). ADR 0003 is amended (Phase-3
   addendum) so this seed use is intentional and **supersedes** the prior wording
   that prohibited seed-derived material from the relationship layer. Historical
   wording is preserved and marked in ADR 0003.
2. **O2 — RK is ephemeral-free by design.** Recoverability does NOT require the
   partner online. Relationship RK is long-lived **for an epoch**. Forward
   secrecy for relationship content is NOT provided by Phase 3. Phase-4
   ratcheting is responsible for forward secrecy. The Phase-3 RK is a wrapping
   key and must never be described as forward-secret.
3. **O3 — MVP server-honored revocation.** A revoked device MUST be prevented by
   the server from participating in new relationship/content operations per this
   protocol. Trust limitation, documented here and in §9:
   - A malicious server can lie about revocation state, withhold revocation
     information, or refuse operations.
   - A revoked/compromised device that already possesses valid keys may retain
     access to ciphertext/key material it already obtained.
   - Revocation does not retroactively erase secrets already held by a device.
   - Client-verifiable signed revocation is deferred to Phase 4.
4. **O4 — Zeroization.** Phase-2 zeroization requirements are inherited
   (ADR 0003 §11): mnemonic, BIP39 seed, derived intermediate secrets,
   temporary private-key material (including pairing ephemeral privates and
   RKA/seed intermediates), and other sensitive transient buffers MUST follow
   the established Phase-2 zeroization requirements wherever the implementation
   environment permits. No new zeroization primitive is introduced.

## 6. Pairing State Machine (revised)

```
  A posts offerConsent_A over offerRecord            B verifies, prepares T,
        │                                             derives RK, checks SAS OOB
        ▼                                                    │
     PENDING ──(B)── acceptConsent_B over T─────────────────────► ACCEPTED
        │  expiry (24h)                                            │  A verifies T + B's
        ▼                                                          │  acceptConsent, checks
     EXPIRED (terminal)                                            │  SAS OOB, signs confirmConsent_A
                                                                   ▼
                                  ESTABLISHED ◄──── both sasProofs present & equal ─── A posts sasProof_A;
                                  (epoch starts)                        B posts sasProof_B
                                                                   │ mismatch → REJECTED (T1 flag)
                                                                   │ timeout → EXPIRED
        REJECTED (responder refuses; pole-authenticated, unsigned) — terminal
        CANCELLED (initiator withdraws from PENDING or ACCEPTED; pole-authenticated, unsigned) — terminal
        TERMINATED (breakup; pole-authenticated, unsigned) — terminal  │ re-key: epoch++, new statics → fresh offer with new transcript (T14/T8 containment)
        MEMORIALIZED (survivor mode — OPEN PRODUCT U1)
```

Rules (unchanged from Revision 1 except consent split):

1. **One active relationship per user pole.** DB partial-unique on
   `(least(userA,userB), greatest(userA,userB))` restricted to non-terminal
   states.
2. **Consent is three signed steps over byte-identical artifacts.** `PENDING`
   requires offerConsent_A. `ACCEPTED` requires acceptConsent_B over the same
   canonical T (returned by the server). `ESTABLISHED` additionally requires
   confirmConsent_A over T AND both sasProofs (equal). Server cannot reach any
   accepting state without the pole that acts in it.
3. **Establish is unforgeable and both-keys-confirmatory.** sasProof equality
   (§5.3) is both key confirmation and transcript confirmation; M cannot compute
   or forge it (no RK), only relay/withhold/fail.
4. **TTL.** Offer expires (`EXPIRED`, e.g. 24h) unless accepted; accepted offers
   are single-use (one ESTABLISHED per transcript; `IDEMPOTENCY_REPLAY`).
5. **SAS is never on the server.** Compared in person / QR, per OPEN PRODUCT U2.
6. **Every transition** validated against stored consents and idempotent;
   terminal states sticky.

## 7. Device Trust & Multi-Device Model

- **Device certificate.** Ed25519 signature over
  `enclave/device-cert-v1` ‖ 0x00 ‖ userId ‖ 0x00 ‖ deviceId ‖ 0x00 ‖
  devicePublicKeyValue ‖ 0x00 ‖ keyVersion. Generated on-device where the
  mnemonic lives; server stores and structurally validates it (Ed25519 vs
  stored identityPublicKey); the **client** does the authoritative verification
  when trusting the partner's devices.
- **Mandatory for relationship participation** (closes T6/T7): no cert ⇒ not a
  valid recipient of relationship material; `DEVICE_CERT_MISSING`.
- **Multi-device, no transport (Model F):** every device of a user re-derives
  RKA from the mnemonic and RK from the partner's relayed statics + epoch. No
  per-device relationship envelopes at all (Model R backs the static via the
  `enclave/device-link-v1` wrap instead — see §5.4).
- **Partner side:** A obtains B's certified device list from the relationship
  view, verifies each cert against B's identityPublicKey before fan-out (T6).
  Server can withhold (availability), not forge (authenticity).
- **Cert lifecycle:** `devices.certSignature/certVersion`; revocation follows
  device revocation (§9); rotation via keyVersion.

## 8. Recovery Interaction (Cases A–D), Model F

**A — user loses one device, still has another.** RK recomputed from
statics+epoch; surviving device refreshes the partner's certified device list.
No server involvement beyond normal reads.

**B — user loses ALL devices; recovers via mnemonic.** Fresh device runs the
Phase-2 proof-of-control flow (ADR 0003 §2), re-derives RKA, refetches the
relationship view (statics + epochNonce public), recomputes RK. Relationship
continuity **without the partner online** — the explicit payoff of an
ephemeral-independent RK.

**C — partner replaces a device while relationship continues.** RKB unchanged
(seed-derived) ⇒ RK unchanged; the new device obtains a cert and joins. No
re-pair.

**D — survivor / death: OPEN PRODUCT U1.** (a) **MEMORIALIZED**: survivor keeps
read+write on RK until it chooses to rotate; (b) **estate delegation**: heir runs
Phase-2 recovery in the deceased's account and re-pairs. Both are crypto-clean;
product picks UX/disclosure.

## 9. Termination, Re-key & Revocation

- **Termination:** pole-authenticated, unsigned (one pole); relationship →
  TERMINATED; epoch closed; clients discard RK; new pairing allowed afterward.
  Established relationships are not subject to the original offer TTL.
- **Re-key (epoch++):** new statics (rotated RKA/RKB) + fresh epochNonce + fresh
  transcript → new RK. Triggered by suspected mnemonic/device compromise (T8 —
  **post-detection containment**, clearly NOT prevention), breakup re-pair, or
  policy. Old epochs burned for new content; active drops re-sealed gradually
  (OPEN PRODUCT U3). **Old ciphertext from closed/burned epochs remains
  ciphertext:** it stays opaque and is only unlockable by whoever holds that
  epoch's RK (or the per-drop content keys) — re-key does not decrypt or rewrite
  it; migrating it is the explicit re-seal path (U3).
- **Revocation (RATIFIED O3, server-honored for MVP):** server marks the device
  revoked (existing `devices.revokedAt`), drops its recovery blob, invalidates
  its device secret, and MUST refuse it new relationship/content operations per
  this protocol; partner clients exclude revoked devices on refresh. Trust
  limitation (documented, not claimed away — see §5.7): a malicious server can
  lie about revocation state, withhold revocation information, or refuse
  operations; a revoked/compromised device that already possesses valid keys may
  retain access to ciphertext/key material it already obtained; revocation does
  not retroactively erase secrets already held by a device. Client-verifiable
  signed revocation is deferred to Phase 4. **Epoch implication:** successful
  revocation stops a revoked device from participating in new operations, but in
  Model F the device already holds the current epoch's RK and may keep opening
  material it obtained before revocation; only a re-key (epoch++) rotates the RK
  and bounds that window — revocation alone does not rotate relationship keys.

## 10. Server Trust Boundary & API/Schema/DB Proposal

### 10.1 What the server may see (operational metadata — REVISED)

| Info                                                                       | Rationale                                                                  |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| relationship static public keys (RKA/RKB) + ephemeral publics              | relayed; signed into T; prove nothing by themselves, co-signed client-side |
| canonical transcript T (byte-exact)                                        | the single object all consents and sasProof digests are over               |
| offer/accept/confirm consent signatures (Ed25519)                          | server validates structure; cannot forge                                   |
| sasProof_A/B (16 bytes)                                                    | compared for equality ONLY — server cannot compute or forge (needs RK)     |
| relationship state transitions, epoch ids, epochNonce (public), timestamps | operational necessity (ADR 0001 D7)                                        |
| ciphertext + per-drop wrapped CK envelopes                                 | opaque (Phase 1/2 guarantees)                                              |
| certified device public key lists                                          | relayed for partner verification                                           |

**Removed from Revision 1:** any SAS artifact (committed or raw) is no longer
stored — a stored commitment would be brute-forceable (20-bit) without a
per-side nonce, and a nonce defeats equality comparison; SAS belongs entirely
client/OOB. The establishment equality check now lives solely in sasProof.

### 10.2 What the server must never see

RKA/RKB private scalars, ephemeral private scalars, RK, per-drop content keys,
SAS values, mnemonic/seed, any plaintext. Enforced by §11 invariants + tests.

### 10.3 Proposed API surface (zod `.strict()`, standard envelope)

- `POST /v1/relationships` — initiator: `{ relationshipStaticPublicKey }` →
  `{ relationshipId, epochNonce, offerRecord, expiresAt }` (offerConsent posted separately as `consentSignature`).
- `GET /v1/relationships` / `GET /v1/relationships/:id` — list / transcript + certified device lists + consents + state.
- `POST /v1/relationships/:id/accept` — responder: `{ transcript, consentSignature, relationshipStaticPublicKey, ephemeralPublicKey }`.
- `POST /v1/relationships/:id/confirm` — initiator: `{ transcript, consentSignature }` + `{ sasProof }`.
- `POST /v1/relationships/:id/establish` — responder posts `{ sasProof }` (both present + equal → ESTABLISHED).
- `POST /v1/relationships/:id/reject` (responder) | `/cancel` (initiator; PENDING or ACCEPTED) — pole-authenticated, unsigned refusals/withdrawal.
- `POST /v1/relationships/:id/rekey` — epoch++ (both consent sigs over new T).
- `POST /v1/relationships/:id/terminate` — end → TERMINATED / MEMORIALIZED (U1).
- `POST /v1/devices` (extended) — registration now requires `certSignature`/`certVersion`.

New error codes: `PAIRING_STATE_INVALID`, `PAIRING_ALREADY_ACTIVE`,
`PAIRING_EXPIRED`, `PAIRING_REJECTED`, `DEVICE_CERT_MISSING`,
`DEVICE_CERT_INVALID`, `RELATIONSHIP_TERMINATED`, `EPOCH_STALE`,
`TOKEN_CONFLICT` (sasProof mismatch), `TRANSCRIPT_MISMATCH`,
`IDEMPOTENCY_REPLAY`.

### 10.4 Proposed DB (design only — no migration written)

- `relationships`: `id`, `user_a`, `user_b` (`a<b`), `state`, `epoch`,
  `epoch_nonce`, `transcript` (text, byte-exact T), `offer_consent`,
  `accept_consent`, `confirm_consent`, `sas_proof_a`, `sas_proof_b`,
  `rka_public_a`, `rka_public_b`, `expires_at`, `established_at`,
  `terminated_at`, timestamps.
- `relationship_epochs`: `id`, `relationshipId`, `epoch`, `epochNonce`,
  `rotation_cause` (initial | rekey | breakup | memorialize), `createdAt`.
- `devices` **adds**: `certSignature`, `certVersion`.
- `encrypted_payloads` **adds**: nullable `relationshipId` (scoping + migration,
  OPEN PRODUCT U3).

## 11. Cryptographic Invariants & Test Strategy

Hard invariants (REVISION-augmented — new numbers marked ★):

1. `RK(A,B) `== `RK(B,A)` for identical (statics, epoch, epochNonce) — TS and
   Dart deterministically (committed vector `pairing-v1.json`, **planned** —
   produced when Phase 3 implementation begins; not yet in
   `packages/contracts/test-vectors/`).
2. Public statics derived from the same mnemonic match across runtimes (§5.3).
3. Server-side Ed25519 verification succeeds iff signature is over the exact
   prefix+`0x00` byte string (consents, certs).
4. No endpoint accepts or returns private material; envelope/error conventions
   hold for every new endpoint.
5. ESTABLISHED unreachable with one consent, or with unequal sasProofs (_both
   required_); REJECTED/EXPIRED/CANCELLED sticky; `IDEMPOTENCY_REPLAY` on reuse.
6. One active relationship per pair → `PAIRING_ALREADY_ACTIVE`.
7. Content-key wrap opens only with true RK; tampered AAD/keyRef fails the tag.
8. Re-key produces a new RK and burns the old epoch for new content.
9. New domain labels never collide with Phase 2 labels (byte-duplicate catch).
10. ★ **RK is independent of the ephemerals:** flipping EKA/EKB public bits in T
    changes sasProof (transcript confirmation fails) but leaves RK unchanged
    (recovery still recomputes). Tested explicitly.
11. ★ **Server cannot forge sasProof:** with all server-visible inputs
    (T, consents, statics), simulated server-side HKDF attempts never reproduce
    either proof (needs RK).
12. ★ **Canonical-T determinism:** both runtimes compute SHA-256 over the same
    server-issued T bytes → identical sasProof given same RK.

Test suites (mirroring Phase-2 pattern): pairing state machine; key
establishment interop (TS↔Dart over `pairing-v1.json`); multi-device
(certified list, rogue refusal T6, revoked exclusion T15); recovery (cases A–D,
no-transport re-derivation); security (T1–T18 table-driven adversaries: key swap
→ sasProof mismatch → REJECTED; signature forgery; replay; epoch confusion;
algorithm-literal pinning; ephemeral perturbation ★).

## 12. Decisions Required (DECIDED / PROPOSED / RATIFIED SECURITY / OPEN PRODUCT DECISION)

### DECIDED (ratified 2026-09-16)

- D1. Primitives/framing/envelope/zod/node:crypto conventions — **reuse, no new
  deps, no ECIES/custom crypto.**
- D2. Device certs identity-signed, mandatory for relationship participation.
- D3. State machine + guards (three signed consents; both-proof equality for
  ESTABLISHED).
- D4. RK excludes ephemerals; sasProof = key confirmation **and** transcript
  confirmation; no SAS artifact on the server.
- D5. New domain labels (§5.2) with non-collision test; `enclave/device-link-v1`
  reserved for Model R only (not used in the ratified MVP).
- D6. Double ratchet stays deferred (D14); 3DH ephemerals live in the transcript
  (authenticated furniture + ratchet seam), not in RK.

### PROPOSED (implementation-ready shape, approved for Phase-3 scope)

- P1. Model F base, RK static-static+epoch (Revision Output item 1), consent/
  confirm flow, sasProof establishment.
- P2. API surface + error codes (§10.3); DB tables/columns (§10.4).
- P3. Legacy device-scoped payloads keep working under their original scope; and
  active drops migrate to relationship-scoped CK wraps over time (re-seal path,
  U3).

### RATIFIED SECURITY DECISIONS (O1–O4, 2026-09-16)

- **O1 — Model F (RATIFIED).** Seed-recomputable relationship static X25519 key.
  ADR 0003 amended (Phase-3 addendum); supersedes prior wording prohibiting
  seed-derived material in the relationship layer. Model R is documented as the
  alternative (§5.4) but is NOT the MVP.
- **O2 — Ephemeral exclusion from RK (RATIFIED).** RK is intentionally
  independent of ephemeral key material; ephemerals stay in T + sasProof. RK is
  a long-lived per-epoch wrapping key; Phase-3 provides no forward secrecy;
  Phase-4 ratcheting owns forward secrecy; RK must not be described as
  forward-secret.
- **O3 — Revocation (RATIFIED, MVP server-honored).** Server MUST prevent a
  revoked device from new relationship/content operations. Limitations
  documented (§5.7/§9): malicious server can lie/withhold/refuse; revoked device
  retains previously obtained material; revocation not retroactive;
  client-verifiable signed revocation deferred to Phase 4.
- **O4 — Zeroization (RATIFIED).** Inherit Phase-2 zeroization (ADR 0003 §11)
  for mnemonic, seed, derived intermediates, ephemeral privates, and sensitive
  transient buffers wherever the environment permits. No new zeroization
  primitive.

### OPEN PRODUCT DECISION (unratified; not crypto-blocking)

- **U1. Survivor/death model (Case D): MEMORIALIZED (recommended) vs estate
  delegation via mnemonic.**
- **U2. SAS UX: 6-digit vs 4-digit+2-emoji vs QR-scan-in-person (QR-first).**
- **U3. Re-key/re-seal migration budget: gradual vs backfill.**
- **U4. Re-key/rotation alerting into the ADR 0003 §9 alerting roadmap**
  (re-affirmed: this is containment, not prevention).

---

## REVISION OUTPUT (six numbered items, per security review)

### 1. Revised RK formula

```
RK = HKDF-SHA512(
  ikm = X25519.scalarMult(RKA_priv, RKB_pub),          // static-static only
  salt = "enclave/relationship-rk-v1",                 // domain separation (salt)
  info = "rk" ‖ 0x00 ‖ relationshipId ‖ 0x00 ‖ epoch  ‖ 0x00 ‖ epochNonce,
  dkLen = 32
)
```

- The `transcriptDigest` (Revision 1) is **removed** from the salt. RK depends
  ONLY on: (a) static-static DH, (b) epoch/version material (`epoch` +
  `epochNonce`), (c) domain separation (+ `relationshipId` pair binding).
- Ephemeral material appears **only** in T (authenticated) and in sasProof's
  info digest — never in RK. Recovery recomputes RK from statics + epochNonce
  (both server-relayable publics) with no transport.
- Consequence (stated, not silently chosen): RK is a long-lived per-epoch
  wrapping key (the ADR 0001 D5 KDK model); no per-message forward secrecy until
  the Phase-4 ratchet layers session keys on top of it (D14).

### 2. Revised transcript definition

`T` = canonical byte-exact UTF-8 JSON (server-issued, zod-validated) with fields
`{t, relationshipId, epochNonce, epoch, a{userId, identityPublicKey,
relationshipStaticPublicKey, ephemeralPublicKey, deviceCert{deviceId,
devicePublicKey, keyVersion, certSignature}}, b{…same…}}`.

- **Ephemeral fields:** `a.ephemeralPublicKey`, `b.ephemeralPublicKey`
  (X25519 publics, fresh per pairing; privates zeroized after establishment).
- **Signed:** `enclave/pairing-consent-v1` ‖ 0x00 ‖ **offerRecord** (offerConsent_A),
  and the same prefix ‖ 0x00 ‖ **T** (acceptConsent_B, confirmConsent_A).
- **Committed:** sasProof_A/B = `HKDF(ikm=RK, salt=enclave/sas-proof-v1,
info=SHA-256(T), dkLen=16)`; SAS committed nowhere (client/OOB only).
- **What SAS authenticates:** OOB congruence of the statics both apps used (same
  ikm as RK → same RK); independent of server relay.
- **What sasProof authenticates:** key confirmation (same RK) AND transcript
  confirmation (same T digest). One-shot, asserted only at ESTABLISHED; later
  devices join under the epoch via certs.
- **Server forgery:** impossible for all four artifacts (needs identity privates
  for consents, RK for proofs). M can only relay, withhold, or fail.

### 3. Revised Model F / R decision — RATIFIED

**Decision: Model F (RATIFIED, 2026-09-16), with the ADR 0003 amendment applied**
(see ADR 0003's Phase-3 addendum; original wording preserved and marked).
Justification (contra the intuition that R is "safer"): Model R does NOT remove
T8 — recovery requires the wrapped static to exist server-side, the seed-derived
wrap key unlocks it, so mnemonic + server defeats confidentiality in both
models. R merely makes the catastrophic case conditional on a user backup having
been taken, at the cost of adding `enclave/device-link-v1` distribution and
losing recovery-without-partner when backup is skipped. F keeps the
first-class-recovery product guarantee with zero transport machinery and a
single explicit ADR-0003 amendment. Full 9-row comparison: §5.4.

### 4. Revised threat analysis for T8

- **Claim:** Model F "prevents" mnemonic compromise — **false**, and removed.
  Re-key + alerting are **post-detection containment** (bound the window after a
  suspected leak is noticed); they do not stop the attacker who already holds the
  mnemonic + server relay.
- **Bounded claim (T8):** mnemonic + **server access** ⇒ full relationship
  content in Model F (recompute RKA, fetch B's statics + epoch, derive RK). In
  Model R, same result **iff** the user's RKA recovery blob exists server-side.
  Mnemonic **alone** (no server) yields nothing in either model (no partner
  statics).
- **Status:** unavoidable for any design that keeps server-mediated recovery and
  seed-derived identity. Prevention would require dropping server-aided recovery
  (contra ADR 0003 D3/first-class recovery) or a PAKE-hardened recovery channel
  (new research; out of scope). **RATIFIED as accepted risk (O1) with
  containment = re-key + alerting (U4).**

### 5. Exact ADR 0003 amendment — APPLIED (see ADR 0003 Phase-3 addendum)

Applied to ADR 0003 as its clearly-marked **Phase-3 addendum**; historical
wording is preserved in place and superseded text is flagged. The amendment text
adopted (identical to the draft ratified by the founders):

> **§1, second bullet** — superseded: "The seed is used for exactly two things:
> **identity signing** (auth/recovery proof) and **recovery wrapping**
> (protecting the backup blob). Neither ever produces a device key or a content
> key." — now reads "... exactly three things: **identity signing**, **recovery
> wrapping**, and **relationship-static derivation** (Model F, ADR 0004): a
> domain-separated X25519 scalar `HKDF-SHA512(seed,
"enclave/relationship-identity-v1", "x25519")`. These three never produce a
> device key or a content key; the relationship static feeds only ECDH inputs."

> **§5, after the attack matrix** — added:
> "The relationship static key is never used to encrypt content. Its only
> outputs are ECDH shared secrets, from which HKDF yields (a) the relationship
> root key RK (wraps per-drop content keys) and (b) an out-of-band SAS for
> pairing verification. RK/SAS never seal content bytes, so the §5 title
> ('Can BIP39-derived material directly decrypt any content? — No.') and the
> attack matrix below are unchanged."

> **§6, layer 3** — superseded: "**Relationship layer** (future, Phase 3+):
> per-relationship wrap keys used with a second user's device keys. Also random,
> never seed-derived." — now reads: "**Relationship layer** (ADR 0004): one
> seed-derived relationship static X25519 key per user (Model F). Its ECDH
> output + HKDF ('enclave/relationship-rk-v1') produce the relationship root key
> RK, which wraps random per-drop content keys — those wrap/content keys remain
> random and never seed-derived; only the _ECDH input_ (the static scalar)
> traces to the seed. This sentence amends the prior wording 'relationship wrap
> keys … never seed-derived': relationship **content/**wrap keys are random; the
> relationship **ECDH input** is seed-derived."

> **§8/§9 note** — appended:
> "Mnemonic compromise also exposes relationship statics (Model F). As with the
> recovery blob (§5 matrix), this is a documented catastrophic self-custody
> case; re-key (ADR 0004 §9) and recovery alerting are post-detection
> containment, not prevention."

### 6. Decisions after ratification

O1–O4 are RATIFIED (see §12 RATIFIED SECURITY DECISIONS and the Ratification
Record below). Remaining **OPEN PRODUCT DECISIONS**:

1. **U1 — survivor/death model (Case D): MEMORIALIZED (recommended) vs estate
   delegation via mnemonic.**
2. **U2 — SAS UX: 6-digit vs 4-digit+2-emoji vs QR-scan-in-person (QR-first).**
3. **U3 — re-key/re-seal migration budget: gradual vs backfill.**
4. **U4 — re-key/rotation alerting into the ADR 0003 §9 alerting roadmap.**

These do not block the ratified cryptographic/state-machine design.

---

## RATIFICATION RECORD (founder, 2026-09-16)

- **O1 — Model F:** RATIFIED for the MVP relationship-key model.
- **O2 — Ephemeral exclusion from RK:** RATIFIED. Ephemerals remain part of the
  authenticated pairing transcript and sasProof confirmation but MUST NOT become
  RK input/key material. Documented: progress recoverability without the partner
  online; RK long-lived per epoch; **Phase 3 does not provide forward secrecy**;
  Phase-4 ratcheting owns forward secrecy; Phase-3 RK is not forward-secret.
- **O3 — Revocation:** RATIFIED — MVP uses server-honored device revocation. A
  revoked device MUST be prevented by the server from participating in new
  relationship/content operations. Trust limitation documented exactly (§5.7/§9):
  malicious server can lie/withhold/refuse; revoked/compromised device retains
  previously obtained key material; revocation is not retroactive;
  client-verifiable signed revocation deferred to Phase 4.
- **O4 — Zeroization:** RATIFIED — inherit Phase-2 zeroization requirements
  (ADR 0003 §11) for mnemonic, seed, derived intermediates, transient private
  material, and sensitive buffers wherever the environment permits. No new
  zeroization primitive.
- **Artifacts:** ADR 0004 status → Accepted (ratified); ADR 0003 amended by its
  Phase-3 addendum (supersessions explicitly marked, historical wording
  preserved). This checkpoint commits documentation only.

---

_Ratified checkpoint (2026-09-16): security decisions O1–O4 accepted; ADR 0004
ratified; ADR 0003 amended with its clearly-marked Phase-3 addendum. No Phase 3
production code, migrations, or routes exist. Remaining open items are the
product decisions U1–U4 shown above._
