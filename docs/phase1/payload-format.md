# Phase 1 — Payload Format (Envelope)

## Envelope specification

Every encrypted payload is stored as a JSON object conforming to `encryptedPayloadEnvelopeSchema` in `packages/contracts/src/payloads.ts`.

### Fields

| Field        | Type                               | Constraints                                              | Description                                                |
| ------------ | ---------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------- |
| `v`          | integer literal `1`                | Version 1                                                | Envelope format version (for future rotation)              |
| `alg`        | string literal `xchacha20poly1305` | Only this algorithm in Phase 1                           | Authenticated encryption algorithm                         |
| `keyRef`     | string                             | ≤255 chars, format `<uuidv7-deviceId>:<keyVersion>`      | Identifies which device key and version was used to seal   |
| `nonce`      | base64 string                      | Decoded length = 24 bytes                                | XChaCha20 nonce (unique per payload; generated via CSPRNG) |
| `ciphertext` | base64 string                      | Decoded length ≥16 bytes (includes 16-byte Poly1305 tag) | Encrypted content + appended authentication tag            |

### Associated Data (AAD)

AAD is constructed as:

```
UTF-8("enclave/payload-v1/<keyRef>")
```

AAD is **not transmitted or stored separately**; it is derived from the `keyRef` field at seal/unseal time. Tampering with `keyRef` causes AEAD tag verification to fail, even if the correct sealing key is used.

### Example

```json
{
  "v": 1,
  "alg": "xchacha20poly1305",
  "keyRef": "01950000-0000-7000-8000-000000000001:0",
  "nonce": "base64-encoded-24-bytes",
  "ciphertext": "base64-encoded-bytes-including-16-byte-tag"
}
```

## Server handling

The server treats the envelope as an **opaque JSON blob**:

1. Validates schema (v, alg, nonce length, ciphertext length)
2. Computes `byteLength` for storage metadata
3. Stores the entire JSON as text in `encrypted_payloads.envelope`

The server **never** parses `ciphertext` or attempts decryption.

## Cross-language compatibility

| Language                  | Library                    | Notes                                                                                                  |
| ------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------ |
| TypeScript (test harness) | `@noble/ciphers/chacha.js` | `xchacha20poly1305(key, nonce, aad).encrypt(data)`; tag appended to output                             |
| Dart (mobile)             | `cryptography ^2.9.0`      | `Xchacha20.poly1305Aead().encrypt(..., aad: aad)`; tag appended to output (SecretBox.cipherText + mac) |

Both produce XChaCha20-Poly1305 AEAD output with a 16-byte appended tag; both
authenticate AAD at the same position (`aadPrefix + keyRef`).

**Verification caveat:** the TypeScript reference-client test suite exercises the
full roundtrip against the live API + Postgres; the Dart test suite verifies
seal/open consistency within a single runtime. A cross-runtime roundtrip
(seal in TS → open in Dart, and reverse) still requires both toolchains in one
environment and is tracked as a remaining verification task.

## Envelope v2 (future considerations)

- Rotating to a new algorithm (e.g., AES-256-GCM)
- Including a payload ID in the envelope (for client-side lookup)
- Both handled via the `v` field to enable graceful migration
