# Phase 1 — Identity Model

**Status:** Implemented (Phase 1 dev-bootstrap; Phase 2 will replace with BIP39 seed-derived identity).

## Current state (dev-bootstrap)

| Concept         | Implementation                                                                               | Production target (Phase 2+)                                      |
| --------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| User ID         | UUIDv7, generated server-side                                                                | BIP39 seed → Ed25519 identity; server-assigned UUIDv7             |
| Authentication  | Server-generated 32-byte secret; Bearer token; verified against SHA-256 digest               | Client-generated BIP39 recovery seed → client-side account secret |
| Device identity | X25519 keypair (public key registered on server); 256-bit random sealing key stays on device | Same + Ed25519 device attestation key; sealed to secure enclave   |
| User count      | No limit enforced at schema level                                                            | Always exactly 2 per product spec (D6)                            |

### What the server knows

- UUIDv7 `user_id`
- SHA-256 digest of the account secret (not the secret itself)
- Device public keys and key version numbers
- Envelope metadata: `deviceId`, `keyVersion`, `algorithm`, envelope `v`
- Timestamps, labels

### What the server never knows

- Account secret plaintext (transmitted once at `/v1/users`, hashed, never returned)
- X25519 private keys
- Device sealing keys
- Plaintext content of any sealed payload

### Phase 1 authentication flow

```
POST /v1/users                ← (server issues secret, returns once)
  ↕ { userId, secret }

POST /v1/devices              ← (Bearer: secret; registers X25519 public key)
  ↕ { deviceId }

POST /v1/payloads             ← (Bearer: secret; stores sealed envelope)
  GET /v1/payloads/:id        ← (Bearer: secret; returns envelope verbatim)
```

This is explicitly a development bootstrap; it is not production authentication and must be replaced before Phase 2 pairing.

## Open items (Phase 2)

- Client-generated BIP39 seed; server returns userId + one-time pairing token
- Device key material derived from seed (not server-generated random)
- Bearer auth replaced with device attestation (signed with Ed25519 device key; server verifies signature against registered public key)
- Account secret derivation: `Argon2id(passphrase) → seed → identity keypair`
