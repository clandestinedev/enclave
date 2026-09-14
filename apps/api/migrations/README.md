# Migrations

Not yet defined. Phase 1 will introduce the identity/device/relationship schema.

Tooling: Drizzle ORM (`drizzle-kit`). Migrations are generated per target dialect and
committed as SQL files:

- `pg` for Postgres (dev + future self-hosted deployments)
- `sqlite` for Cloudflare D1 (early cost-optimized MVP)

All migration files are pinned with content checksums so replay is verifiable across
infrastructure moves (see ADR 0001). Business logic must never depend on a specific
dialect — access happens behind repository interfaces.
