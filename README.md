# Enclave

> Where it's just you two.

A private social network exclusively for two people in a relationship. No followers, no
stranger discovery, no public feed — the entire social graph contains exactly one person:
your partner.

## Principles

- **Privacy first.** The server is untrusted infrastructure. Content is encrypted
  end-to-end on-device; the backend stores ciphertext and minimal operational metadata
  only.
- **No backdoors.** Recovery is the user's own seed material. There is no server-side
  plaintext pipeline.
- **Provider-agnostic.** Cloudflare is an early host, not the permanent home. Identity,
  data, media, contracts, and keys survive migration to a VPS, a cluster, or private
  infrastructure.
- **Relationship-first.** One relationship. Two users. Every boundary derives from that.

## Stack

| Layer      | Choice                                                                                 |
| ---------- | -------------------------------------------------------------------------------------- |
| Mobile     | Flutter / Dart (Android + iOS)                                                         |
| Backend    | TypeScript + Hono                                                                      |
| Database   | Drizzle ORM, Postgres-first (D1-compatible target)                                     |
| Media      | Abstracted storage (R2 / S3 / MinIO / local)                                           |
| Encryption | libsodium-class primitives: Ed25519, X25519, XChaCha20-Poly1305, HKDF, Argon2id, BIP39 |

## Repository layout

```
apps/api            Hono + TypeScript backend
apps/mobile         Flutter mobile app (skeleton)
packages/contracts  Shared wire contracts (TS)
infra               Docker Compose (Postgres + MinIO), deploy targets
docs/adr            Architecture Decision Records
```

## Development

Backend requires Node >= 22.

```sh
npm install
npm run dev -w @enclave/api   # start API on :3000
npm test                       # unit / API tests
npm run typecheck              # strict typecheck across workspaces
npm run lint                   # eslint
npm run build                  # production build
```

Local infra (Postgres on :5433, MinIO on :9000/9001):

```sh
docker compose -f infra/docker-compose.yml up -d
```

Mobile requires the Flutter toolchain. Run `flutter create .` inside `apps/mobile` once
the SDK (FVM) is installed to scaffold `android/` / `ios/` platform directories.

## Status

Phase 0 — architecture + repository + tooling. See `docs/adr/0001-architecture-foundation.md`.
