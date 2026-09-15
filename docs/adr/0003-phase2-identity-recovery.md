# ADR 0003 — Phase 2 Identity & Recovery Model (BIP39)

- **Status:** Proposed — pending founder sign-off (explicitly NOT implementation-ready)
- **Date:** 2026-09-15
- **Deciders:** Engineering (principal architect) — two product founders
- **Scope:** BIP39 identity derivation, proof-of-control recovery protocol, device key model, key separation, revocation, mnemonic lifecycle, server recovery metadata

## Context

ADR 0002 established the Phase 1 device key model (random X25519 keypair + random 256-bit sealing key) and an explicitly temporary dev-bootstrap account secret. Phase 2 replaces the account secret with a BIP39-derived identity so an account can be recovered across device loss without trusting the server.

BIP39 is a **mnemonic-to-seed standard**; it is not an encryption scheme and not an authorization protocol. This ADR therefore defines the actual proof-of-control protocol that turns seed possession into account recovery.

## 1. Exact cryptographic identity derived from the BIP39 seed

```
phrase (12 words, 128-bit entropy)                  — the recovery artifact, user-held
   │  PBKDF2-HMAC-SHA512(password=phrase, salt="mnemonic", iter=2048, dkLen=64)   [BIP39 spec]
   ▼
seed (64 bytes)                                     — never persisted, wiped after derivation
   │  HKDF-SHA512(ikm=seed, salt="enclave/identity-signing-v1", info="ed25519", dkLen=32)
   ▼
identity signing private key (32 bytes, Ed25519)    — proof-of-control key
   ▼
identityPublicKey (32 bytes, Ed25519 / base64)      — the ONLY thing the server ever learns
```

- The seed itself is never an account identifier and is never transmitted.
- `identityPublicKey` is the on-server anchor for the account: it is what the server verifies signatures against. It is **not** proof of anything by itself.
- A parallel HKDF output produces the **recovery wrapping key** (see §5) — the seed does not act as a single monolithic "account key."
- Derivation uses `HKDF-SHA512` with an explicit domain-separation salt, mirroring the cross-runtime approach already verified for XChaCha20 (noble + `cryptography` both implement Ed25519 and HKDF-SHA512). Ed25519 seed → keypair is built into both libs.

## 2. Proof-of-control protocol (challenge-response, NOT public-key presence)

Possession of `identityPublicKey` must **not** be accepted as proof. The server requires a valid Ed25519 signature over a server-issued, single-use, expiring challenge that is bound to (a) the account and (b) the proposed new device.

### Flow (recovery of an existing account)

```
Client                                       Server
  │  1. POST /v1/recovery/challenge             │
  │     body: { identityPublicKey }            │
  │────────────────────────────────────────────▶│ checks account exists (by identityPublicKey)
  │  2. 200 { challengeId, nonce, ttl }        │ issues single-use nonce, TTL 30 min,
  │◀────────────────────────────────────────────│ binds nonce↔accountId↔identityPublicKey
  │  3. sign Ed25519 over:                      │
  │     "enclave/recovery-v1"                   │
  │     ‖ accountId (uuid)                      │
  │     ‖ challengeId (uuid)                    │
  │     ‖ newDevicePublicKeyValue (base64)      │
  │  4. POST /v1/recovery/complete              │
  │     { challengeId, signature,               │
  │       newDevice: { publicKey, keyVersion } }│
  │────────────────────────────────────────────▶│ 5. verifies nonce unused+unexpired,
  │                                                signature over exact bytes against
  │                                                stored identityPublicKey,
  │                                                then registers the new device
```

Security properties:

- **Active possession, not presence:** only the holder of the seed-derived private key can produce a valid signature (Ed25519 unforgeability). A captured `identityPublicKey` or a replayed old signature is useless because the nonce is single-use and fresh.
- **Challenge binding:** `challengeId` is single-use (server marks it consumed atomically) and expiring. A signed response for device A cannot be replayed to enroll device B — the new device public key is inside the signed input.
- **Domain separation:** the `enclave/recovery-v1` prefix prevents a recovery signature from being re-presented as any other kind of signed object.
- **First-device provisioning uses the same protocol** at account creation: the server refuses to store an `identityPublicKey` until a challenge signed over (identityPublicKey ‖ nonce) is supplied — so identity registration is itself authenticated, preventing key-substitution.
- **Server cannot forge recovery:** it holds only `identityPublicKey`; it never holds the seed or the signing key. Recovery always requires the user's active signature.

## 3. How a new device is authorized after recovery

1. The recovered device generates its own fresh material locally: X25519 keypair + random 256-bit sealing key (identical to ADR 0002 D1). Nothing device-key-related is derived from the seed.
2. It completes §2 challenge/complete, authorizing **that device's public key** for the account.
3. The server registers the device and issues device-scoped API credentials (replaces the Phase 1 dev-bootstrap secret; a real per-device credential).
4. The new device then downloads the account's recovery blobs (§12), unwraps prior device sealing keys with the recovery wrapping key, and stores them in secure storage as read-only legacy keys so it can open already-sealed payloads. New payloads it seals use its own fresh sealing key.

## 4. How device keys relate to the recovered identity

Device keys are **independent random material**, never derived from the seed:

```
deviceId ──► X25519 keypair (public part registered)
          ──► sealing key: 32 random CSPRNG bytes (seals payloads, ADR 0002)
```

- The seed is used for exactly two things: **identity signing** (auth/recovery proof) and **recovery wrapping** (protecting the backup blob). Neither ever produces a device key or a content key.
- Device sealing keys are _recoverable_ only because a wrapped copy is stored server-side (§5/§12), encrypted under the seed-derived wrapping key.

## 5. Can BIP39-derived material directly decrypt any content? — No.

Payload-level confidentiality rests **only** on per-device sealing keys (ADR 0002). Seed-derived material never touches ciphertext:

- `identity signing key` → signs challenges; cannot decrypt anything.
- `recovery wrapping key` (HKDF `"enclave/recovery-wrap-v1"`) → wraps/encrypts **keys**, never content.

The one strong-reason exception that is allowed and intended:

> The wrapping key must decrypt the **recovery blob** (which contains device sealing keys). This is wrapping of key material for disaster recovery — the required behavior. Even then, content bytes require first unwrapping a device sealing key; the seed alone (with no blob) decrypts nothing, and the blob alone (with no seed/wrapping key) decrypts nothing.

Attack matrix:

| Attacker has            | Confidentiality of payload content               |
| ----------------------- | ------------------------------------------------ |
| Server DB (full)        | Preserved — envelopes opaque, blobs encrypted    |
| Recovery blob only      | Preserved — blob is wrapped                      |
| Mnemonic only           | Preserved — no device sealing keys available     |
| Mnemonic + blob         | **Defeated** — this is exactly recovery          |
| A live, unlocked device | Defeated — device holds real keys (out of scope) |

## 6. Relationship keys and content keys stay separate from identity/recovery keys

Three disjoint layers:

1. **Identity/recovery layer** (seed-derived): identity signing key, recovery wrapping key.
2. **Content layer** (random per device, Phase 1 → per-payload in Phase 3): sealing keys, payload envelopes. Content keys are never seed-derived.
3. **Relationship layer** (future, Phase 3+): per-relationship wrap keys used with a second user's device keys. Also random, never seed-derived.

Rules:

- A seed compromise never decrypts content directly (matrix above).
- A content-key compromise never leads to another user's relationship keys (no shared derivation).
- Identity rotation (future) must not require re-sealing payloads: content keys wrap under device sealing keys, not under identity keys.

## 7. Device revocation

- Server marks the device `revoked` and immediately invalidates its API credentials; subsequent authenticated requests fail.
- The server deletes (or disables) that device's recovery blob entry, so the revoked device's sealing key is no longer restorable via recovery.
- Payloads sealed under the revoked device remain encrypted but unreadable until the account restores them via another authorized route (recovery re-enrolls a fresh device which unwraps surviving blobs / re-seals).
- Re-enrolling **the same** device is not re-authorized by its old key; it must go through the §2 proof-of-control flow again with fresh device material.

## 8. All devices lost

1. User installs the app fresh and enters the mnemonic.
2. §2 challenge-response derives the identity signing key, proves control, and enrolls a fresh device.
3. The new device downloads the account's recovery blobs, unwraps prior device sealing keys, and gains read access to legacy payloads. It can also re-seal/re-encrypt under its own key over time.
4. **Hard failure case (documented, accepted):** if the server also lost the blobs (or the account's blobs were purged, or the seed is gone), the content is cryptographically unrecoverable. Enclave does not keep an escrow/backdoor.

## 9. Recovery mnemonic compromised

The mnemonic is the root of the account's _identity_, so its compromise is by design the worst case:

- The attacker can run §2 themselves (they can sign), enroll their own device, unwrap blobs, and read all recoverable content; the legitimate user is locked out.
- Mitigations **in this ADR**:
  - Recommended **BIP39 passphrase** (optional 25th word) is a user-supplied string appended to the BIP39 seed derivation (BIP39 supports it natively). This raises offline brute-force cost by user-chosen entropy and is not stored anywhere by Enclave or the server. Enforced for the "high-assurance" account tier.
  - Recovery events must be server-logged and (Phase 4+) alerted (e.g., email/notification on new-device enrollment) so a silent takeover is harder to do unnoticed.
  - No device or account operation ever re-displays the mnemonic; it exists only at creation and reentry.
- Accepted: without passphrase + alerts, mnemonic compromise == identity compromise. This is standard for self-custodial systems; it is why secure, offline backup guidance (§11) is mandatory.

## 10. 12 words vs 24 words

**Decision: 12 words (128-bit) default; 24 words (256-bit) available for an opt-in "high-assurance" tier.**

- Brute force is not the real threat: 128-bit entropy is far beyond feasible offline guessing, and BIP39 fixes PBKDF2 at only 2048 iterations regardless of phrase length. The marginal 128→256 bits add no practical brute-force defense.
- The actual threat is **capture** (theft, screenshot, shoulder-surf, transcription error, social engineering). Longer phrases raise transcription error rate and user friction without improving capture resistance.
- The optional passphrase provides the meaningful extra factor: 12 words + a strong unknown passphrase is materially stronger than 24 words alone, because the passphrase is memorized (not written down) while the words are backed up offline.
- 24 words stays available for institutional/regulatory assurance and for users who insist on a documentable higher floor.

## 11. Mnemonic lifecycle (generation → display → confirm → backup → erase)

| Stage    | Requirement                                                                                                                                                                                                                                                                                                                                              |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Generate | Platform CSPRNG (`Random.secure` / `crypto.getRandomValues`), BIP39 wordlist (English, standard, checksum-validated), 12 words default. Wordlist must be the same canonical BIP39 list in both runtimes (single committed asset + byte-interop test, mirroring interop-v1.json).                                                                         |
| Display  | Single screen, dimmed/privacy mode, screenshots and screen-recording blocked on the platform (iOS/Android privacy flag), no PII overlays, auto-dismiss timer. Never displayed again afterward.                                                                                                                                                           |
| Confirm  | Re-enter **sampled words** (e.g., positions 4/7/9) to prove transcription; re-derive seed internally and verify it reproduces `identityPublicKey` before accepting.                                                                                                                                                                                      |
| Backup   | Mandatory in-app guidance: write on paper offline, multiple copies in separate physical locations, no photos, no cloud/email/notes apps, no clipboard.                                                                                                                                                                                                   |
| Erase    | Mnemonic, seed, and HKDF intermediates are zeroed from memory immediately after confirmation and **never persisted** in app storage, keychain/keystore, logs, crash reports, or backups. Only derived artifacts persist: `identityPublicKey` and the recovery blob. The app cannot reveal the mnemonic after setup (recovery requires fresh user entry). |

## 12. Server metadata to support recovery — without gaining decryption capability

The server stores _only_:

- **accounts**: `accountId`, `identityPublicKey` (Ed25519), `identityKeyVersion`, timestamps.
- **devices**: `deviceId`, X25519 `publicKey`, `keyVersion`, `status` (active/revoked), timestamps.
- **recovery blobs**: `blobId`, `accountId`, `deviceId`, opaque base64 blob `envelope` — content is the device sealing key wrapped under the seed-derived recovery wrapping key (AAD-bound to `accountId + blobId`). Server treats it as opaque bytes; it cannot decrypt it.
- **challenges**: `challengeId`, `accountId`, `nonce`, `expiresAt`, `usedAt` (single-use enforcement).
- payload envelopes as in Phase 1 (opaque to server).

Never stored server-side: mnemonic, BIP39 seed, any seed-derived private key or wrapping key, any device sealing key in the clear, any content key.

## Open decisions to ratify with this ADR

1. Derivation scheme: `HKDF-SHA512` domain-separated (chosen) vs a BIP32/SLIP-0010 path. HKDF is chosen for verifiable byte-interop and minimal moving parts, but it is a decision founders should ratify.
2. 12-word default + passphrase enforcement for high-assurance tier (§10) — confirm tiering.
3. Recovery alerting (Phase 4+) as a mandatory roadmap item for §9 mitigation.
4. Blob purge policy: blobs persist until account deletion or device revocation (accepted in §7/§8).

## Consequences

### Positive

- Recovery is user-sovereign: proof-of-control is a genuine signature challenge, not public-key presence; server cannot forge or block recovery, only facilitate it.
- Strong layering: identity/recovery keys, device keys, and content keys are disjoint; seed material never encrypts content.
- Revocation and mnemonic-compromise handling are explicit, with documented hard-failure cases.

### Accepted trade-offs

- Mnemonic compromise of an account without passphrase/alerting = full identity takeover (standard self-custody position).
- First-device + new-device provisioning depend on the challenge protocol, so cryptographic work happens on-device during onboarding.
- Blob retained server-side means a host compromise plus a mnemonic leak defeats confidentiality (documented attack matrix).

## Status

Proposed. **No implementation as of this ADR.** Founder approval of §10 (word count/tiering) and Open decision #1 (HKDF vs BIP32) is required before Phase 2 implementation begins. Pending also: ADR 0002 sign-off.
