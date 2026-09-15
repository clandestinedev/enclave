# Phase 1 Documentation Index

| Document                                | Contents                                                                      |
| --------------------------------------- | ----------------------------------------------------------------------------- |
| [Identity Model](identity-model.md)     | User/device identity, dev-bootstrap vs production, server knowledge boundary  |
| [Trust Model](trust-model.md)           | Server-as-untrusted-courier, what server sees/doesn't, enforcement mechanisms |
| [Key Ownership](key-ownership.md)       | Who holds which keys, key lifecycle, secrets that must never be logged        |
| [Payload Format](payload-format.md)     | Envelope schema, AAD policy, cross-language compatibility, server handling    |
| [Recovery Status](recovery-status.md)   | Phase 1 gaps, Phase 2 recovery model, device key lifecycle                    |
| [Native Dev Setup](native-dev-setup.md) | Prerequisites, native Postgres setup, running API/tests/Dart core             |

## ADRs

| ADR                                                                                  | Status       | Scope                                                      |
| ------------------------------------------------------------------------------------ | ------------ | ---------------------------------------------------------- |
| [ADR 0001 — Architecture Foundation](../adr/0001-architecture-foundation.md)         | Accepted     | Monorepo, identity, key hierarchy, trust model, data layer |
| [ADR 0002 — Payload Encryption Protocol](../adr/0002-payload-encryption-protocol.md) | **Proposed** | Device sealing key, AAD, crypto libraries, Dart SDK        |
