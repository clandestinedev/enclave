# Phase 1 — Trust Model

Derived from ADR 0001 D7 ("server is untrusted infrastructure").

## What the server IS

- An untrusted courier: it receives opaque envelopes, stores them, routes them, and returns them verbatim.
- The server cannot distinguish encrypted content from random bytes (sealed with XChaCha20-Poly1305; tag indistinguishable from ciphertext to an observer).

## What the server can see (operational metadata)

| Visible to server                      | Rationale                                            |
| -------------------------------------- | ---------------------------------------------------- |
| Device public keys                     | Needed to register devices; never secret             |
| Envelope structure: `{v, alg, keyRef}` | Needed to validate schema; does not reveal plaintext |
| Payload byte length                    | Accepted trade-off; useful for storage accounting    |
| Timestamps (created_at, last_seen_at)  | Operational necessity                                |
| Device labels                          | User-chosen; not sensitive                           |
| User/device count                      | Operational metadata                                 |

## What the server CANNOT see

| Hidden from server        | Mechanism                                                                        |
| ------------------------- | -------------------------------------------------------------------------------- |
| Plaintext content         | Sealed with device sealing key; server has no access                             |
| Sealing key               | Never transmitted; lives in device secure storage only                           |
| X25519 private key        | Never transmitted; used only locally for future ECDH (Phase 2)                   |
| Other users' key material | Cross-user queries are rejected (enforced by auth middleware + ownership checks) |

## Enforcement mechanism (Phase 1)

1. **Envelope validation** (contracts `encryptedPayloadEnvelopeSchema`): rejects malformed envelopes at the route level before storage; server never attempts decryption.
2. **Device ownership check**: `POST /v1/payloads` verifies the `deviceId` extracted from `keyRef` belongs to the authenticated user; a device from User A cannot store payloads under User B's device ID.
3. **Ownership isolation**: `GET /v1/payloads/:id` checks the payload's `userId` matches the authenticated user.
4. **Revocation enforcement**: `PayloadService` rejects payloads from revoked devices.
5. **No decryption on server**: No endpoint decrypts payloads; no test decrypts payloads; no logging of payload content.

## AAD binding (Phase 1)

The `keyRef` inside the envelope is authenticated (AAD = `enclave/payload-v1/<deviceId>:<keyVersion>`), which binds the ciphertext to the specific device and key version. Tampering with `keyRef` causes decryption failure even if the correct sealing key is used.
