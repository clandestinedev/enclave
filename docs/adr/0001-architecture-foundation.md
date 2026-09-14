# ADR 0001 — Architecture Foundation & Key Management

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** Engineering (principal architect) — two product founders
- **Scope:** Repository layout, identity, key hierarchy, trust model, storage, data layer,
  deployment portability, and the Phase 0→1 boundary.

## Context

Enclave is a private social network for exactly two people in a relationship. The product
is built around a single, deliberate pair.

Non-negotiable constraints from the product spec:

1. The backend is **untrusted infrastructure** — it must never require plaintext access
   to messages, media, captions, thoughts, comments, or replies.
2. The app is **offline-first** with client-side encryption; the server coordinates
   ciphertext and minimal metadata.
3. Identity belongs to the application (stable UUID/ULID-style IDs), **not** to the
   infrastructure provider (Cloudflare IDs, DB auto-increments, storage-provider IDs).
4. Infrastructure is replaceable: Cloudflare today, VPS/cluster/private hardware later —
   without rebuilding the app or touching ciphertext/keys/accounts.
5. No custom cryptography. Mature, audited primitives only. No silent backdoors.
6. Lost-device recovery is a first-class requirement.

## Decisions

### D1. Repository layout — npm workspaces monorepo

```
apps/
  api/          Hono + TypeScript backend
  mobile/       Flutter / Dart app
packages/
  contracts/    shared wire contracts (TypeScript source consumed by api)
infra/          docker-compose (dev), Terraform targets, deploy config
docs/adr/       decision records
```

- `apps/mobile` is not an npm package (Dart toolchain is installed separately).
- Wire contracts live in one package so the API and mobile never drift. Mobile gets a
  hand-maintained Dart mirror, pinned against `WIRE_VERSION`.

### D2. Identity — application-owned, UUIDv7

- Every entity (user, device, relationship, drop, media) uses **UUIDv7** IDs: stable,
  sortable, cryptographically unguessable, infrastructure-agnostic.
- A username is a non-primary, cosmetic label only.
- No Cloudflare/D1/R2/auto-increment identifiers are ever exposed as public identity.

### D3. Root of trust — user recovery seed (BIP39)

- Each user's root of trust is a **BIP39 mnemonic seed** generated on-device.
- All identity keys are derived deterministically from the seed.
- The seed is the sole server-independent recovery path. Losing it means the account
  content is permanently unrecoverable (there is no server-side backdoor).
- **Explicit UX requirement:** the app must honestly communicate this during onboarding
  (paper backup / encrypted export). This is the price of a server that cannot read.

### D4. Cryptographic stack (no custom crypto)

| Primitive          | Use                                                |
| ------------------ | -------------------------------------------------- |
| BIP39 + BIP32/HKDF | seed → deterministic key derivation                |
| Ed25519            | user identity signing key, device attestations     |
| X25519             | relationship ECDH (static-static), device exchange |
| XChaCha20-Poly1305 | payload seal (confidentiality + integrity)         |
| Argon2id           | passphrase hardening for seed/backup material      |
| HKDF-SHA256        | key derivation / domain separation                 |

Backend uses the same primitives only for **metadata and attestation verification** — it
never decrypts user payloads.

### D5. Key hierarchy

```
BIP39 seed (recovery, on-device)
├─ Ed25519 signing keypair      → user identity
├─ X25519 identity keypair      → ECDH input for relationship key
└─ per-device key material      → device auth (secure enclave / Android Keystore / iOS Keychain)

Relationship (derived independently by both partners — no key transport needed):
  KDK = HKDF( X25519(A_priv, B_pub) == X25519(B_priv, A_pub) )
        → a symmetric wrapping key known only to the two users

Per Drop / Memory:
  DropKey = random 256-bit         → encrypts that drop's content
  DropKey is wrapped: E_KDK(DropKey)  → sent to server, server cannot unwrap
```

- Content is encrypted with a **fresh random key per drop**; the relationship key is only
  used to wrap those per-drop keys. This bounds the blast radius of any single compromise.
- Server stores only ciphertext + wrapped keys + nonces + salt. Never plaintext keys.
- Devices can be **revoked** by rotating device attestations; per-drop keys turn over
  independently.
- **Forward secrecy is deferred** (D14).

### D6. Relationship model — exactly two users

- `relationships` has exactly two members. No followers, no public graph.
- The relationship key is implicitly derived via static-static X25519 ECDH from both
  users' seeds — pairing requires only exchanging public identity keys, after which both
  clients derive the same wrapping key with no key material crossing the server.
- Every content/authorization query is constrained by relationship membership.
- **Isolation is tested explicitly:** User A must never reach User B's relationship data.

### D7. Trust model — server is untrusted

- End-to-end encryption at the client. Server handles encrypted payloads, delivery,
  routing, and operational metadata only.
- Thumbnails/previews are generated and encrypted **on-device**. No plaintext media
  pipeline or plaintext thumbnail pipeline exists on the backend.
- Metadata minimization: the server may know object existence, sizes, timestamps,
  delivery state, and integer reaction codes. It does not know captions, contents, or
  comment/reply text (those are encrypted).
- Logs never contain plaintext content, keys, or sensitive tokens.

### D8. Media storage abstraction

- `MediaStorage` interface: logical `media_id` in, provider out.
  Implementations: R2, S3, MinIO (local), future datacenter storage.
- Objects are stored as client-side ciphertext. **Ciphertext is portable** — migrating
  providers is a copy + metadata update, never a re-encryption.
- `media_objects` track provider, bucket, object key, encrypted size, ciphertext SHA-256,
  encryption algorithm/nonce, and lifecycle state.

### D9. Data layer — Drizzle ORM, Postgres-first

- Repositories sit behind interfaces; business logic is blind to the engine.
- **Dev runs on Postgres** (installed locally); Cloudflare D1 (SQLite) is an acceptable
  early MVP host.
- `drizzle-kit` generates migrations per dialect (pg, sqlite). Migration SQL files are
  committed with **content checksums** so replay is verifiable across infrastructure moves.

### D10. Backend portability — Hono

- One codebase, two runtimes: Cloudflare Workers (early) and Node (`@hono/node-server`).
- Cloudflare-specific behavior (bindings, R2, D1, push) is isolated behind `adapters/`.
- API is stateless; horizontally scalable later with no code change.

### D11. Content model — unified "Drop"

- One content model (`drops`) covering photo, video, meme, text, audio, location; a Drop
  may become a Memory by reference — **no duplicate media**.
- Reactions v1 are **integer codes** from a fixed taxonomy (server learns only the
  category, never free text). Fully encrypted reactions are deferred.
- Comments and replies are encrypted like Drop payloads.

### D12. Streaks, memories, notifications

- Streaks/memories derive from plaintext operational metadata (timestamps, delivery),
  never from content.
- Push (FCM/APNs) carries **minimal, content-free payloads** ("Your person dropped
  something."). Providers may learn that a drop event occurred at time T — accepted.

### D13. Identity survives infrastructure changes

- UUIDv7 IDs + deterministic keys from user seeds mean accounts, relationships, wrapped
  keys, and ciphertext carry over to any future host unchanged.

### D14. Forward secrecy — deferred

- Static-static ECDH yields a long-lived relationship wrapping key; it does not provide
  per-message forward secrecy.
- Mitigation for v1: random per-drop keys (D5) bound exposure, and revocation rotates
  device capabilities.
- A Signal-style double-ratchet (per-device messaging + per-message keys) is the documented
  upgrade path for messaging. Explicitly not in MVP.

## Consequences

### Positive

- Server compromise does not reveal user content.
- Infrastructure migration never requires rewriting the app, re-encrypting media, or
  re-keying users.
- Clean seams for testing isolation, key lifecycle, and storage portability.

### Negative / accepted trade-offs

- Recovery is entirely on the user (seed). Support cannot restore data.
- No forward secrecy for historical content if a wrapping key is compromised (v1).
- Server sees operational metadata (times, sizes, delivery, reaction categories).
- Push providers observe delivery events.

### Explicit sign-off held open for founders

1. Seed-only recovery UX (D3).
2. No forward secrecy in v1 (D14).
3. Integer reaction taxonomy as server-visible metadata (D7/D11).
4. Plaintext operational metadata (timestamps/streak indicators) visible to the backend.

Any reversal of these four requires a new ADR.

## Phase 0 → 1 boundary

- Phase 0 (this commit): repository, tooling, CI, contracts, health, ADR.
- Phase 1: authentication/identity + device registration, with end-to-end encryption
  round-trip tests, key lifecycle, and device revocation before any multi-device sync.
