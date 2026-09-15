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
packages/dart_core  Pure-Dart client crypto core (headless-tested)
infra               Docker Compose (Postgres + MinIO), deploy targets
docs/adr            Architecture Decision Records
docs/phase1         Phase 1 docs (trust model, keys, payload format, recovery)
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

The canonical development DB is native Postgres on :5432 (Docker is optional):

```sh
scripts/db-bootstrap.sh
npm run dev -w @enclave/api
```

See `docs/phase1/native-dev-setup.md` for the full setup.

Mobile requires the Flutter toolchain. Run `flutter create .` inside `apps/mobile` once
the SDK (FVM) is installed to scaffold `android/` / `ios/` platform directories. The
client crypto core is independent and can be verified headlessly:

```sh
cd packages/dart_core && dart pub get && dart test
```

## Status

Phase 1 — identity (dev-bootstrap), device registration, E2EE payload roundtrip.
See `docs/phase1/` and `docs/adr/0002-payload-encryption-protocol.md`.
