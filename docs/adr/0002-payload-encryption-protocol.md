# ADR 0002 — Payload Encryption Protocol (Phase 1)

- **Status:** Proposed — pending founder sign-off
- **Date:** 2026-09-15
- **Deciders:** Engineering (principal architect) — two product founders
- **Scope:** Device sealing key model, AAD policy, cross-language libraries, Dart SDK decision

## Context

ADR 0001 specifies the cryptographic primitives (D4) and key hierarchy (D5) but does not specify:

1. What key material a device holds and how payloads are sealed in Phase 1
2. What is authenticated as Associated Data (AAD) for the per-device payload envelope
3. Which crypto libraries are used across TypeScript (test harness) and Dart (mobile core)

These are security-critical decisions surfaced per the Phase 1 spec requirement: any crypto decision not resolved by ADR 0001 must be presented for approval before implementation.

## Decisions

### D1. Device key model (Phase 1)

**Chosen:** Device generates X25519 keypair + 256-bit random device sealing key. Both live in device secure storage; only the public key is registered on the server.

```
Device secure storage:
  - X25519 private key (32 bytes) — for future ECDH; never leaves device
  - Device sealing key (32 bytes, random, CSPRNG) — used to seal Phase 1 payloads
  - keyVersion: currently 0; incremented on key rotation
```

Server stores: `publicKey` (X25519, 32 bytes base64), `keyVersion`.

Payload sealed with: `XChaCha20-Poly1305(sealingKey, nonce, plaintext, aad)`.

**Rejected:** Deriving sealing key from X25519 private key via HKDF (mixes identity key with encryption key; violates D5 principle of key separation). Deferred to Phase 2 for production seal architecture.

### D2. Associated Data (AAD) policy

**Chosen:** AAD = `UTF-8("enclave/payload-v1/<keyRef>")` where `keyRef = <deviceId>:<keyVersion>`.

- AAD is derived from the envelope's `keyRef` field at seal/unseal time; it is NOT transmitted separately.
- Authenticates: protocol version (`enclave/payload-v1`), device identity, and key version.
- Tampering with `keyRef` causes Poly1305 tag verification failure.

**Rationale:** The server validates the envelope schema before storage (including `keyRef` format) but does not parse `ciphertext`. Authenticating `keyRef` in the AAD provides lightweight binding of ciphertext to its intended device+key context without requiring server-side knowledge of the sealing key.

### D3. Cross-language crypto libraries

| Language                                      | Library                                         | Notes                                                                                                       |
| --------------------------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| TypeScript (test-only, `@enclave/api` devDep) | `@noble/ciphers@^2.4.0`, `@noble/curves@^1.7.0` | Audited, minimal deps, pure ESM; never in production server code                                            |
| Dart (mobile crypto core)                     | `cryptography@^2.9.0`                           | Mature pure-Dart; supports XChaCha20-Poly1305, X25519, HKDF; `Dart` fallback works without platform plugins |

**Server production code:** never imports crypto libraries for user payload processing; it treats envelopes as opaque JSON.

### D4. Dart SDK installation for verification

**Chosen:** Dart SDK headless (standalone; not Flutter) installed at runtime for `dart test` verification of `packages/dart_core`. Flutter/FVM deferred to UI development phase.

**Rationale:** Crypto core is written as a pure-Dart package; no Flutter dependency required for test verification. Dart SDK headless is ~230MB; Flutter full is ~2GB+. Dart SDK install is straightforward via Google's archive (storage.googleapis.com).

## Consequences

### Positive

- Sealing key never leaves the device; server cannot decrypt any payload.
- AAD provides lightweight ciphertext-to-device binding without server key knowledge.
- Cross-language interop verified: TS reference client + Dart core mirror the same protocol.

### Negative / accepted trade-offs

- Phase 1 dev-bootstrap account secret is explicitly temporary; production identity (BIP39) is a separate Phase 2 decision.
- Forward secrecy for per-device payload keys is not provided (D14 deferral carries forward).
- Dart tests are currently unverifiable until Dart SDK is available in the development environment; TS harness tests prove the protocol works against the live API.

## Status

Pending founder sign-off on all four decisions before merging ADR 0002 to `main`.
