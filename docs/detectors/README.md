# RustDefend Detectors

RustDefend includes **45 detectors** across 4 smart contract ecosystems plus cross-chain dependency analysis.

## Detector Categories

| Chain | Count | Detectors |
|-------|-------|-----------|
| [Solana](solana/) | 14 | SOL-001 through SOL-014 |
| [CosmWasm](cosmwasm/) | 9 | CW-001 through CW-009 |
| [NEAR](near/) | 10 | NEAR-001 through NEAR-010 |
| [ink!](ink/) | 10 | INK-001 through INK-010 |
| [Cross-chain](common/) | 2 | DEP-001, DEP-002 |

## Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 11 |
| High | 25 |
| Medium | 8 |
| Low | 1 |

## Machine-Readable Index

See [all_detectors.json](all_detectors.json) for structured metadata (id, name, description, severity, confidence, chain).

## Severity Calibration

Severities reflect 2024+ ecosystem mitigations:

- **CW-001** (integer overflow): Critical -> Medium. CosmWasm Uint128/256 panics on overflow (safe revert).
- **CW-002** (reentrancy): Medium -> Low. CosmWasm actor model is non-reentrant by design.
- **INK-002** (integer overflow): Critical -> Low. `cargo-contract` enables overflow-checks by default.
- **SOL-009** (CPI reentrancy): Confidence Medium -> Low. Solana account locking mitigates.
