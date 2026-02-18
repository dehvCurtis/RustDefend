# RustDefend Detectors

RustDefend includes **61 detectors** across 4 smart contract ecosystems plus cross-chain dependency analysis.

## Detector Categories

| Chain | Count | Detectors |
|-------|-------|-----------|
| [Solana](solana/) | 21 | SOL-001 through SOL-021 |
| [CosmWasm](cosmwasm/) | 13 | CW-001 through CW-013 |
| [NEAR](near/) | 12 | NEAR-001 through NEAR-012 |
| [ink!](ink/) | 11 | INK-001 through INK-011 |
| [Cross-chain](common/) | 4 | DEP-001 through DEP-004 |

## Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 12 |
| High | 30 |
| Medium | 16 |
| Low | 3 |

## Machine-Readable Index

See [all_detectors.json](all_detectors.json) for structured metadata (id, name, description, severity, confidence, chain).

## Severity Calibration

Severities reflect 2024+ ecosystem mitigations:

- **CW-001** (integer overflow): Critical -> Low. CosmWasm Uint128/256 panics on overflow (safe revert).
- **CW-002** (reentrancy): Medium -> Low. CosmWasm actor model is non-reentrant by design. Only flags IBC/reply handlers.
- **INK-002** (integer overflow): Critical -> Low. `cargo-contract` enables overflow-checks by default.
- **SOL-009** (CPI reentrancy): Confidence Medium -> Low. Solana account locking mitigates.

## False Positive Filters

All detectors include FP reduction filters validated against 6 real-world repositories (521 findings, ~65% estimated TP rate):

### Cross-Cutting

- **Global:** Test file/directory exclusion (`/tests/`, `_test.rs`, `#[test]`)
- **Call graph analysis:** Before emitting a finding, checks if any caller in the same file already performs the relevant security check (signer, owner, input validation). Helper functions called from checked entry points are not flagged
- **Workspace chain detection:** In monorepos, each crate's `Cargo.toml` is read independently. SOL detectors only run on Solana crates, CW detectors only on CosmWasm crates, etc. — eliminates cross-chain noise

### Per-Detector

- **SOL-001:** Skips internal helpers (`_*`, `handle_*`), utility functions (`validate*`, `parse*`), non-signer params (`sysvar`, `pda`, `vault`, `config`), `process_*` sub-handlers, CPI wrapper helpers (`transfer`, `burn`, `mint_to`, etc.), framework library paths
- **SOL-003:** Requires Solana-specific source markers (no cross-chain FPs). Skips math helper functions (`calculate_*`, `compute_*`, `*_fee`, `*_rate`), assert/require-guarded functions, pack/serialization functions, SPL library paths
- **SOL-010:** Skips Anchor codegen, intentionally global PDAs (`b"config"`, `b"state"`, `b"vault"`)
- **SOL-012:** Skips framework/library source paths (SPL, Anchor) and codegen files
- **INK-002:** Requires ink!-specific source markers (`#[ink(`, `ink_storage`, `ink_env`) — no cross-chain FPs
- **INK-003:** Skips known permissionless patterns (`flip`, `increment`, `vote`), PSP22/PSP34 standard methods (`transfer`, `approve`)
- **CW-001:** Downgraded to Low/Low; skips test/mock functions and test file paths
- **CW-002:** Only flags IBC/reply handlers (CosmWasm is non-reentrant by design)
- **CW-009:** Skips mock/helper/setup functions and test-related file paths (`integration_tests/`, `multitest/`)
- **NEAR-010:** Skips NEP standard methods (`ft_transfer`, `nft_mint`, `storage_deposit`, etc.)
