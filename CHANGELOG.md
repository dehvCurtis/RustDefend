# Changelog

All notable changes to RustDefend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.1] - 2026-02-17

### Added

- **Vulnerability name in findings** — all output formats (text, JSON, SARIF) now show the detector name as a title (e.g. "Missing Owner Check") alongside the detector ID
- 8 new FP-specific unit tests across 6 detectors (139 total tests)

### Changed

- **CW-001** (integer overflow): Downgraded from Medium/Medium to **Low/Low** — Uint128/Uint256 panics are safe reverts, not exploitable. Skips test/mock/helper functions
- **CW-002** (reentrancy): Now only flags IBC handlers, reply handlers, and SubMsg dispatchers — CosmWasm is non-reentrant by design. Non-IBC execute handlers no longer flagged

### Fixed

- **SOL-001** FP reduction: Skip internal helpers (`_*`, `inner_*`, `do_*`, `handle_*`), utility functions (`validate*`, `serialize*`, `parse*`), expanded non-signer param exclusions
- **SOL-010** FP reduction: Skip Anchor codegen files and functions, recognize intentionally global PDAs (`b"config"`, `b"state"`, `b"vault"`, etc.)
- **INK-003** FP reduction: Skip known permissionless patterns (`flip`, `increment`, `vote`), PSP22/PSP34 standard methods (`transfer`, `approve`)
- **CW-009** FP reduction: Skip mock/helper/setup functions and test-related file paths
- Updated test fixtures for SOL-010 and CW-002 to match new FP filters

## [0.3.0] - 2026-02-16

### Added

- **5 new detectors** for medium-priority coverage gaps (50 total)
  - CW-010: Unguarded migrate entry — detects migrate handler without admin/sender check or version validation
  - CW-011: Missing reply ID validation — detects reply handler not matching on msg.id
  - NEAR-011: Unguarded storage unregister — detects storage_unregister without balance/force checks
  - NEAR-012: Missing gas for callbacks — detects cross-contract calls without explicit gas specification
  - INK-011: Unguarded set_code_hash — detects set_code_hash usage without admin/owner verification
- Test fixtures for all 5 new detectors

## [0.2.0] - 2026-02-16

### Added

- **5 new detectors** for actively exploited 2024+ vulnerability classes (45 total)
  - SOL-012: Token-2022 extension safety — detects programs accepting Token-2022 tokens without checking for dangerous extensions (PermanentDelegate, TransferHook, MintCloseAuthority)
  - SOL-013: Unsafe remaining_accounts — detects ctx.remaining_accounts usage without owner/type/key validation
  - SOL-014: init_if_needed reinitialization — detects Anchor init_if_needed without guard checks
  - CW-008: Unsafe IBC entry points — detects IBC packet handlers without channel validation or timeout rollback
  - DEP-002: Supply chain risk indicators — detects wildcard versions, unpinned git deps, and known-malicious crate names
- Test fixtures for all 5 new detectors
- Known malicious crate name database (10 crates from 2024-2025 supply chain attacks)

## [0.1.0] - 2026-02-13

### Added

- **40 detectors** across 4 chains + cross-chain dependency analysis
  - Solana (11): SOL-001 through SOL-011
  - CosmWasm (8): CW-001 through CW-007, CW-009
  - NEAR (10): NEAR-001 through NEAR-010
  - ink! (10): INK-001 through INK-010
  - Cross-chain (1): DEP-001
- AST-based analysis via `syn` crate (no regex)
- Auto-detects chain from `Cargo.toml` dependencies
- Parallel file processing via `rayon`
- Output formats: text (colored), JSON, SARIF v2.1.0
- Inline suppression: `// rustdefend-ignore` and `// rustdefend-ignore[SOL-001]`
- Severity and confidence filtering
- Per-detector filtering by ID
- Quiet mode for CI/CD (exit code only)

### Changed

- **Severity calibration** for 2024+ ecosystem mitigations:
  - CW-001 (integer overflow): Critical -> Low (CosmWasm Uint128/256 panics on overflow)
  - CW-002 (reentrancy): Medium -> Low (CosmWasm actor model is non-reentrant by design, only IBC/reply flagged)
  - INK-002 (integer overflow): Critical -> Low (`cargo-contract` enables overflow-checks by default)
  - SOL-009 (CPI reentrancy): Confidence Medium -> Low (Solana account locking mitigates)

### Fixed

- SOL-003 false positive filters: skip literals, string concatenation, widening casts, `checked_*`/`saturating_*`/`wrapping_*`, pack/serialization functions
- INK-003 risk stratification: Critical for sensitive fields, High for general writes, Medium/Low for permissionless patterns
