# Task 1: Severity/Confidence Recalibration

**Priority:** P0 (Quick Win)
**Estimated Effort:** Small
**Status:** Planned

## Summary

Adjust severity and confidence levels for 5 detectors based on 2024+ ecosystem research. These detectors flag issues that are either mitigated by framework defaults or architecturally prevented.

## Changes

### CW-001 (cosmwasm-integer-overflow)
- **File:** `src/detectors/cosmwasm/integer_overflow.rs`
- **Change:** Severity Critical -> **Medium**
- **Reason:** CosmWasm `Uint128`/`Uint256` operators panic on overflow by default. This safely aborts the transaction (no state corruption). Using `checked_*` is better practice for graceful error handling, but the current behavior is a code quality issue, not a security vulnerability.
- **Update description** to note that panics are safe reverts
- **Update recommendation** to explain that `checked_*` enables graceful handling vs panic

### CW-002 (cosmwasm-reentrancy)
- **File:** `src/detectors/cosmwasm/reentrancy.rs`
- **Change:** Confidence Medium -> **Low**
- **Reason:** CosmWasm's actor model is non-reentrant by design. Messages dispatch only after execution completes. CEI violations are informational best-practice findings, not exploitable.
- **Update description** to note the architectural non-reentrancy
- **Update recommendation** to note IBC-hooks exception (CWA-2024-007)

### INK-002 (ink-integer-overflow)
- **File:** `src/detectors/ink/integer_overflow.rs`
- **Change:** Severity Critical -> **Low**
- **Reason:** `cargo-contract` enables Rust's `overflow-checks` by default. Arithmetic panics on overflow at runtime. Only relevant if developers manually disable overflow checks in Cargo.toml.
- **Update description** to note cargo-contract default
- **Update recommendation** to note when this becomes relevant (manual disable)

### SOL-009 (cpi-reentrancy)
- **File:** `src/detectors/solana/cpi_reentrancy.rs`
- **Change:** Confidence Medium -> **Low**
- **Reason:** Solana's single-threaded execution and account locking model mitigates CPI reentrancy. Still flagged for defense-in-depth.
- **Update description** to note Solana's account locking
- **Update recommendation** to note this is defense-in-depth

### INK-001 (ink-reentrancy)
- **NO CHANGE.** Correctly flags explicit `set_allow_reentry(true)` opt-in. Critical/High is appropriate for intentional risky behavior.

## Verification

- [ ] `cargo build` compiles without errors
- [ ] `cargo test` — all 70 tests pass
- [ ] `cargo run -- list-detectors` shows updated severity/confidence
- [ ] Re-scan test contracts — verify CW-001/INK-002 no longer appear under `--severity critical`
- [ ] JSON output reflects new severity values

## Impact

- Users filtering by `--severity critical` will see fewer noise findings
- CW-001 (47 findings) and INK-002 (2 findings) drop out of critical
- CW-002 (5 findings) and SOL-009 (16 findings) drop out of `--confidence medium` filter
- Total critical findings reduced by ~49
