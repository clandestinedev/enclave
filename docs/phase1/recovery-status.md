# Phase 1 — Recovery Status

## Current status: no user recovery path (Phase 1 is dev-bootstrap)

Phase 1 implements a server-generated account secret, returned once. If lost, the user cannot authenticate again. This is intentional for Phase 1 dev-bootstrap and is **not production recovery**.

### Phase 1 recovery gap (accepted)

| Scenario            | Phase 1 outcome                                                                                                  | Phase 2 target                                                                                   |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Account secret lost | User cannot authenticate; no recovery path                                                                       | BIP39 seed backup (paper/wallet export); seed restores all keys                                  |
| Device lost         | Payloads encrypted with that device's sealing key are permanently unrecoverable (sealing key was on device only) | Device revocation + key re-wrapping with relationship key; other partner's device retains access |
| Both devices lost   | Total data loss                                                                                                  | Seed backup → re-derive keys; or partner's device remains accessible                             |
| Server compromise   | No user data revealed (server holds only ciphertexts)                                                            | Same; this is the core guarantee                                                                 |

### Phase 2 recovery model (from ADR 0001 D3)

- BIP39 mnemonic seed generated on-device
- All identity keys derived deterministically from seed
- Seed = sole server-independent recovery path
- App must communicate this honestly: paper backup / encrypted export required before any data is created
- No server-side backdoor for recovery

### Device key lifecycle (recovery-relevant)

| Event                         | Key effect                                                                           | Recovery impact                                |
| ----------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------- |
| Device registration           | Sealing key created; stored in device secure storage                                 | New device = new sealing key                   |
| Device revocation             | Server rejects payloads from that device                                             | Partner's device still has its own sealing key |
| Sealing key rotation (future) | `keyVersion` increments; old payloads remain decryptable if sealed under old version | Smooth; multiple key versions stored           |

## Explicit sign-off required (per ADR 0001)

Seed-only recovery UX (D3) is listed as an open founder sign-off item. Until explicit sign-off, no server-side recovery mechanism will be implemented.
