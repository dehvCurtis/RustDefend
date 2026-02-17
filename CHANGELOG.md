# Changelog

All notable changes to RustDefend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
  - CW-001 (integer overflow): Critical -> Medium (CosmWasm Uint128/256 panics on overflow)
  - CW-002 (reentrancy): Medium -> Low (CosmWasm actor model is non-reentrant by design)
  - INK-002 (integer overflow): Critical -> Low (`cargo-contract` enables overflow-checks by default)
  - SOL-009 (CPI reentrancy): Confidence Medium -> Low (Solana account locking mitigates)

### Fixed

- SOL-003 false positive filters: skip literals, string concatenation, widening casts, `checked_*`/`saturating_*`/`wrapping_*`, pack/serialization functions
- INK-003 risk stratification: Critical for sensitive fields, High for general writes, Medium/Low for permissionless patterns
