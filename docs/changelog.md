# Changelog

## 0.1.0

Initial release.

### Detectors (40)

- **Solana (11):** SOL-001 through SOL-011
- **CosmWasm (8):** CW-001 through CW-007, CW-009
- **NEAR (10):** NEAR-001 through NEAR-010
- **ink! (10):** INK-001 through INK-010
- **Cross-chain (1):** DEP-001

### Features

- AST-based analysis via `syn` crate (no regex)
- Auto-detects chain from `Cargo.toml` dependencies
- Parallel file processing via `rayon`
- Output formats: text (colored), JSON, SARIF v2.1.0
- Inline suppression: `// rustdefend-ignore` and `// rustdefend-ignore[SOL-001]`
- Severity and confidence filtering
- Per-detector filtering by ID
- Quiet mode for CI/CD (exit code only)

### Severity Calibration

Severities reflect 2024+ ecosystem mitigations:

- CW-001 (integer overflow): Critical -> Medium. CosmWasm Uint128/256 panics on overflow (safe revert).
- CW-002 (reentrancy): Medium -> Low. CosmWasm actor model is non-reentrant by design.
- INK-002 (integer overflow): Critical -> Low. `cargo-contract` enables overflow-checks by default.
- SOL-009 (CPI reentrancy): Confidence Medium -> Low. Solana account locking mitigates.

### False Positive Reduction

SOL-003 (integer overflow) FP filters:

- Skip literal-only and literal+variable arithmetic
- Skip string concatenation patterns
- Skip `.len()` / `as usize` patterns
- Skip `checked_*` / `saturating_*` / `wrapping_*` lines
- Skip widening casts: `(a as u128) * (b as u128)`
- Skip pack/serialization functions (`pack_into_slice`, `unpack_from_slice`, etc.)
- Division reported at Low confidence (cannot overflow)

INK-003 (missing caller check) risk stratification:

- Critical: writes to sensitive fields (owner, admin, authority, controller)
- Critical: transfers value without auth
- High: general storage writes without caller check
- Medium/Low: payable or caller-scoped writes (likely permissionless by design)

### Ground Truth Baseline (2026-02-13)

Re-ran baseline with all 40 detectors against pinned test corpus commits. See `GROUND_TRUTH_BASELINE.md`.

- **691 total findings** across 7 test repositories (up from 605 with 32 detectors)
- **95 unit tests**, all passing
- **No regressions** in any of the original 32 detectors
- **+86 new findings** from Task 4 detectors: SOL-010 (+48), NEAR-010 (+19), CW-009 (+17), INK-010 (+6), SOL-011 (+2)
- **~56% estimated true positive rate** (down from ~59% due to SOL-010 FPs on Anchor codegen)
- All test corpus commits pinned for reproducibility
- 11 detectors with zero findings documented with reasons
- Coverage gaps updated to reflect 2024-2026 threat landscape
