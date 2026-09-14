# Infra

## Local dev stack

```sh
docker compose up -d
```

- Postgres 18 on host port **5433** (5432 left free for any local Postgres install)
- MinIO (S3-compatible object storage) API on **9000**, console on **9001**
- Credentials are dev-only (see volumes below)

## Deployment targets

Per ADR 0001, the API must run anywhere:

1. **Cloudflare** (Workers + D1 + R2) — early cost-optimized MVP
2. **VPS** — Postgres + MinIO (or S3/R2) behind a proxy
3. **VPS cluster → dedicated → private infrastructure**

All provider-specific access is isolated behind `adapters/` in the API. Identity,
relationships, encrypted media, keys, and wire contracts never depend on the provider.
