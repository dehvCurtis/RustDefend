# RustDefend Detectors

RustDefend includes **50 detectors** across 4 smart contract ecosystems plus cross-chain dependency analysis.

## Detector Categories

| Chain | Count | Detectors |
|-------|-------|-----------|
| [Solana](solana/) | 14 | SOL-001 through SOL-014 |
| [CosmWasm](cosmwasm/) | 11 | CW-001 through CW-011 |
| [NEAR](near/) | 12 | NEAR-001 through NEAR-012 |
| [ink!](ink/) | 11 | INK-001 through INK-011 |
| [Cross-chain](common/) | 2 | DEP-001, DEP-002 |

## Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 11 |
| High | 25 |
| Medium | 12 |
| Low | 2 |

## Machine-Readable Index

See [all_detectors.json](all_detectors.json) for structured metadata (id, name, description, severity, confidence, chain).

## Severity Calibration

Severities reflect 2024+ ecosystem mitigations:

- **CW-001** (integer overflow): Critical -> Low. CosmWasm Uint128/256 panics on overflow (safe revert).
- **CW-002** (reentrancy): Medium -> Low. CosmWasm actor model is non-reentrant by design. Only flags IBC/reply handlers.
- **INK-002** (integer overflow): Critical -> Low. `cargo-contract` enables overflow-checks by default.
- **SOL-009** (CPI reentrancy): Confidence Medium -> Low. Solana account locking mitigates.

## False Positive Filters

All detectors include FP reduction filters:

- **Global:** Test file/directory exclusion (`/tests/`, `_test.rs`, `#[test]`)
- **SOL-001:** Skips internal helpers (`_*`, `handle_*`), utility functions (`validate*`, `parse*`), non-signer params (`sysvar`, `pda`, `vault`, `config`)
- **SOL-010:** Skips Anchor codegen, intentionally global PDAs (`b"config"`, `b"state"`, `b"vault"`)
- **INK-003:** Skips known permissionless patterns (`flip`, `increment`, `vote`), PSP22/PSP34 standard methods (`transfer`, `approve`)
- **CW-001:** Downgraded to Low/Low; skips test/mock functions
- **CW-002:** Only flags IBC/reply handlers (CosmWasm is non-reentrant by design)
- **CW-009:** Skips mock/helper/setup functions and test-related file paths
