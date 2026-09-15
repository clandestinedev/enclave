# Phase 1 — Mobile Architecture Boundaries

The mobile app (Flutter, `apps/mobile`) uses clean layers. Crypto lives ONLY in the
presentation-independent core; UI code never calls crypto primitives directly.

## Layer map

```
apps/mobile/                     Flutter app (UI, navigation, features)
  lib/
    features/                    Feature screens (feed, memories, settings…)
    ui/                           shared widgets, theme
    core/
      crypto/                     → imports package:enclave_crypto (crypto core)
      storage/                    → secure storage bindings + repository interfaces
      networking/                 → API client (HTTP/JSON envelope models)
```

The crypto core is a **separate pure-Dart package** — `packages/dart_core`
(`package:enclave_crypto`) — so it can be:

- unit-tested headlessly with the plain Dart SDK (no Flutter),
- shared without Flutter bindings,
- verified against the TypeScript reference client in `apps/api/test/reference-client.ts`.

`apps/mobile` depends on it via a path dependency (`package:enclave_crypto`), declared
once Flutter tooling is installed.

## Crypto core — public surface (packages/dart_core)

| Symbol                                       | Purpose                                    |
| -------------------------------------------- | ------------------------------------------ |
| `createDeviceKeyMaterial()`                  | X25519 keypair + 256-bit sealing key       |
| `sealPayload(material, deviceId, plaintext)` | → envelope JSON for POST /v1/payloads      |
| `openPayload(material, envelopeJson)`        | → plaintext; throws on tamper/AAD mismatch |
| `parseEnvelope(json)`                        | strict server-equivalent schema validation |

## Secure storage boundary (Flutter)

The following MUST only be handled by `core/storage`, never by the crypto core or UI:

| Material           | Binding target (not implemented in Phase 1)                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| X25519 private key | iOS Keychain / Android Keystore (via `flutter_secure_storage` or platform channel) |
| Device sealing key | StrongBox / Secure Enclave-backed storage                                          |
| Account secret     | iOS Keychain / Android Keystore                                                    |

`core/crypto` receives these as plain `Uint8List`/`DeviceKeyMaterial` already loaded by
`core/storage`. Crypto never persists anything.

## Networking boundary

`core/networking`:

- Serializes envelopes to JSON and POSTs `{v, alg, keyRef, nonce, ciphertext}`.
- Never reads plaintext fields; the envelope is opaque to the API client.
- Auth header is supplied by `core/storage` (no plaintext secret on `core/networking`).

## Rules (non-negotiable)

1. UI code never imports `package:cryptography`.
2. Crypto core never imports `flutter`, never touches IO or storage — pure functions only.
3. Plaintext exists only transiently inside the crypto call stack; no logging of it anywhere.
4. Envelope schema is mirrored from `packages/contracts` (hand-maintained Dart mirror,
   pinned to `WIRE_VERSION`) — the two must never drift independently.
