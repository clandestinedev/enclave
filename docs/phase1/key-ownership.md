# Phase 1 — Key Ownership

## Key material inventory (Phase 1)

| Key                                 | Owner                                    | Stored                                                | Transmission                                           |
| ----------------------------------- | ---------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------ |
| Account secret (32-byte random)     | Server (hashed) + User (plaintext, once) | Server: SHA-256 digest only; User: app secure storage | Transmitted once via `/v1/users` response; never again |
| X25519 device public key            | User device                              | Server: `devices.publicKeyValue` column (plaintext)   | Transmitted at device registration; never deleted      |
| X25519 device private key           | User device only                         | Device secure storage (not in DB, not in logs)        | Never transmitted                                      |
| Device sealing key (256-bit random) | User device only                         | Device secure storage (not in DB, not in logs)        | Never transmitted                                      |

## Why the server has public keys but not private keys

Public keys are needed for two reasons:

1. **Device registration proof**: server must verify that the user actually possesses a valid key (the public key is what the server stores to link a `deviceId` to a user).
2. **Future key exchange (Phase 2)**: when two partners pair, X25519 ECDH requires both public keys; the server relays the second partner's public key to the first, enabling the relationship key derivation.

The server never needs to decrypt payloads, so it never needs sealing keys or private keys.

## Device sealing key lifecycle

```
Creation:     generated randomly when a device is first registered
Storage:      device secure storage (Keychain / Keystore / iOS Keychain)
Rotation:     when keyVersion increments (currently 0; future rotation TBD)
Revocation:   device revoked → key material discarded; payloads sealed under
              that key remain readable only by devices holding the sealing key
```

## Relationship keys (Phase 2, documented for completeness)

Per D5, the relationship key derivation uses X25519 static-static ECDH between both users' identity keys → HKDF → relationship KDK. This is a future step; Phase 1 establishes device identity only.

## Secrets that must never be logged or transmitted

- X25519 private keys
- Device sealing keys
- Account secret plaintext (after initial receipt)
- Payload plaintext or decrypted content

These are explicitly excluded from all logs, error messages, and responses.
