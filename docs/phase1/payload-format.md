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

## Canonical byte encoding

The values that cross the wire are fixed-format bytes; base64 is only the
JSON transport encoding. **Test vectors must be reproducible byte-for-byte, so
this section is canonical and normative** for both the TypeScript reference
client and the Dart mobile core.

### Encoding rules

| Item               | Canonical encoding                                                               |
| ------------------ | -------------------------------------------------------------------------------- |
| X25519 private key | 32 raw bytes (the RFC 7748 scalar/seed as consumed by the `cryptography` lib)    |
| X25519 public key  | 32 raw bytes (u-coordinate, clamped/output)                                      |
| Sealing key        | 32 raw bytes (256-bit CSPRNG symmetric key)                                      |
| Nonce              | 24 raw bytes; **not** reused across payloads unless byte-exact vector test       |
| AAD                | `UTF-8("enclave/payload-v1/" + keyRef)`, `keyRef` = `<deviceId>:<keyVersion>`    |
| Plaintext          | Authenticated _and_ encrypted exactly as supplied (no length prefix, no padding) |
| Envelope fields    | **standard** base64 (RFC 4648 with `+` `/` `=`), not base64url, both runtimes    |

### Ciphertext / tag layout

The sealed `ciphertext` field is a single byte string laid out as:

```
+----------------+------------------+
| AEAD output    | 16-byte tag      |
| (len(payload)) | (Poly1305)       |
+----------------+------------------+
```

- Total length = `len(plaintext) + 16`.
- The **16-byte Poly1305 authentication tag is appended at the end**, never
  split or reordered; every implementation must append (on seal) and strip the
  final 16 bytes (on open) to recover the raw AEAD output.
- The tag authenticates: the ciphertext, the AAD (`aadPrefix + keyRef`), and
  (implicitly) the key version because `keyRef` is part of the AAD.
- Both libraries emit this layout natively:
  - TypeScript (`@noble/ciphers/chacha.js`): `xchacha20poly1305(key, nonce, aad).encrypt(data)`
    returns `ciphertext ‖ tag`; `.decrypt(ct)` accepts the same concatenation.
  - Dart (`cryptography`): `SecretBox.cipherText ‖ SecretBox.mac.bytes`
    (Dart seals as `[...box.cipherText, ...box.mac.bytes]`).

### Committed deterministic test vector

`packages/contracts/test-vectors/interop-v1.json` is the canonical
cross-language artifact. It fixes **all** inputs (X25519 private key, public
key, sealing key, nonce, AAD, plaintext, envelope) so no runtime randomness is
needed to assert interoperability. The keys and plaintext are test-only and
safe to commit.

Both suites assert **byte-identical** output against this vector and recover
the plaintext from it (see the "Cross-language compatibility" section), proving:

- TS seal (noble) == vector == Dart seal (`cryptography`) with the same inputs;
- TS open recovers plaintext from the vector; Dart open recovers plaintext from
  the same bytes.

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

**Cross-language verification (done):** a committed deterministic test vector
(`packages/contracts/test-vectors/interop-v1.json`) is exercised from both
runtimes with **no randomness**. The Dart suite (`test/interop_test.dart`) and
the TypeScript suite (`apps/api/test/interop.test.ts`) both assert that their
seal output with the vector's fixed nonce is byte-identical to the vector
ciphertext, and that opening the vector ciphertext returns the vector
plaintext. See the "Committed deterministic test vector" section above for the
exact assertions.

## Envelope v2 (future considerations)

- Rotating to a new algorithm (e.g., AES-256-GCM)
- Including a payload ID in the envelope (for client-side lookup)
- Both handled via the `v` field to enable graceful migration
