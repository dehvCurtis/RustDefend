# RustDefend

Static security scanner for Rust smart contracts. Analyzes source code via AST parsing (`syn` crate) to detect vulnerabilities across Solana, CosmWasm, NEAR, and ink! ecosystems.

- **40 detectors** covering the most common smart contract vulnerability classes
- **AST-based analysis** — parses Rust source into syntax trees, no regex pattern matching
- **Auto-detects chain** from `Cargo.toml` dependencies (solana-program, cosmwasm-std, near-sdk, ink)
- **Parallel file processing** via `rayon` for fast scans on large codebases
- **Multiple output formats** — colored text, JSON, SARIF v2.1.0
- **Severity calibrated** to 2024+ ecosystem mitigations (e.g., CosmWasm overflow panics, ink! overflow checks, Solana account locking)

## Installation

Requires Rust 1.70+.

```bash
git clone https://github.com/dehvCurtis/RustDefend.git
cd RustDefend
cargo install --path .
```

Or build without installing:

```bash
cargo build --release
# Binary at target/release/rustdefend
```

## Usage

### Scan a project

```bash
rustdefend scan /path/to/project
```

The chain is auto-detected from `Cargo.toml` dependencies. To force a chain:

```bash
rustdefend scan /path/to/project --chain solana
```

### Filter results

```bash
# Only critical and high severity
rustdefend scan . --severity critical,high

# Only high-confidence findings
rustdefend scan . --confidence high

# Run specific detectors
rustdefend scan . --detector SOL-001,SOL-003

# Quiet mode (exit code only: 0=clean, 1=findings)
rustdefend scan . --quiet
```

### Output formats

```bash
rustdefend scan . --format text    # colored terminal output (default)
rustdefend scan . --format json    # JSON array
rustdefend scan . --format sarif   # SARIF v2.1.0 for CI/CD
```

### List detectors

```bash
rustdefend list-detectors
rustdefend list-detectors --chain near
```

## Detectors

40 detectors across 4 chains + cross-chain dependency analysis:

### Solana (11)

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| SOL-001 | Missing signer check | Critical | High |
| SOL-002 | Missing owner check | Critical | High |
| SOL-003 | Integer overflow | Critical | Medium |
| SOL-004 | Account confusion (missing discriminator) | High | Medium |
| SOL-005 | Insecure account close | High | Medium |
| SOL-006 | Arbitrary CPI | Critical | Medium |
| SOL-007 | PDA bump misuse | High | High |
| SOL-008 | Unchecked CPI return | High | High |
| SOL-009 | CPI reentrancy (CEI violation) | Medium | Low |
| SOL-010 | Unsafe PDA seeds | High | Medium |
| SOL-011 | Missing rent exemption | Medium | Medium |

### CosmWasm (8)

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| CW-001 | Integer overflow | Medium | Medium |
| CW-002 | Reentrancy (CEI violation) | Low | Low |
| CW-003 | Missing sender check | Critical | Medium |
| CW-004 | Storage prefix collision | High | High |
| CW-005 | Unchecked query response | High | Low |
| CW-006 | Improper error handling (panic in entry point) | High | High |
| CW-007 | Unbounded iteration | High | Medium |
| CW-009 | Missing address validation (`Addr::unchecked`) | High | Medium |

### NEAR (10)

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| NEAR-001 | Promise reentrancy | Critical | Medium |
| NEAR-002 | Signer vs predecessor confusion | High | High |
| NEAR-003 | Storage staking auth bypass | High | Medium |
| NEAR-004 | Callback unwrap usage | High | High |
| NEAR-005 | Wrapping arithmetic on balances | Critical | Medium |
| NEAR-006 | Missing #[private] on callback | Critical | High |
| NEAR-007 | Self-callback state inconsistency | High | Medium |
| NEAR-008 | Frontrunning risk | High | Low |
| NEAR-009 | Unsafe storage keys | Medium | Medium |
| NEAR-010 | Missing deposit check on #[payable] | High | High |

### ink! (10)

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| INK-001 | Reentrancy (allow_reentry) | Critical | High |
| INK-002 | Integer overflow | Low | Medium |
| INK-003 | Missing caller check | Critical | Medium |
| INK-004 | Timestamp dependence | Medium | Medium |
| INK-005 | Unbounded storage growth | Medium | Medium |
| INK-006 | Unchecked cross-contract call | High | High |
| INK-007 | Panic in message/constructor | High | High |
| INK-008 | Result suppression (`let _ =`) | Medium | Medium |
| INK-009 | Unsafe delegate call | Critical | High |
| INK-010 | Missing payable check | Medium | Medium |

### Cross-chain (1)

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| DEP-001 | Outdated dependencies with known CVEs | High | High |

See [docs/detectors/](docs/detectors/) for detailed descriptions, false positive filters, and severity rationale.

## CI/CD Integration

### GitHub Actions (SARIF)

```yaml
- name: Run RustDefend
  run: |
    rustdefend scan . --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings detected |

Use `--quiet` to suppress all output and rely only on the exit code.

## Inline Suppression

Suppress findings with comments:

```rust
let total = amount + fee; // rustdefend-ignore
let total = amount + fee; // rustdefend-ignore[SOL-003]
```

- `rustdefend-ignore` suppresses all detectors for that line
- `rustdefend-ignore[ID]` suppresses a specific detector

## Architecture

```
src/
  cli.rs              # CLI argument parsing (clap)
  main.rs             # Entry point
  lib.rs              # Library root
  scanner/
    mod.rs            # File discovery, parallel dispatch (rayon)
    context.rs        # Per-file scan context (AST, source, chain)
    finding.rs        # Finding struct, severity/confidence enums
  detectors/
    mod.rs            # Detector trait, registry
    solana/           # SOL-001 through SOL-011
    cosmwasm/         # CW-001 through CW-007, CW-009
    near/             # NEAR-001 through NEAR-010
    ink/              # INK-001 through INK-010
    common/           # DEP-001 (cross-chain)
  utils/
    ast_helpers.rs    # AST traversal utilities
    chain_detect.rs   # Chain auto-detection from Cargo.toml
  report/
    text.rs           # Colored terminal output
    json.rs           # JSON array output
    sarif.rs          # SARIF v2.1.0 output
```

Each detector implements the `Detector` trait and is registered in its chain's `mod.rs`. The scanner parses each `.rs` file into a `syn` AST and passes it through all registered detectors for the detected chain.

## Ground Truth Baseline

A reproducible baseline is maintained against 7 open-source test repositories with pinned commit hashes. Current results (2026-02-13):

- **691 findings** across 7 repos
- **95 unit tests**, all passing
- **~56% estimated true positive rate**

See [GROUND_TRUTH_BASELINE.md](GROUND_TRUTH_BASELINE.md) for full details.

## Development

```bash
# Run tests
cargo test

# Build release
cargo build --release

# Scan the test corpus
rustdefend scan test-contracts/solana/spl --chain solana
rustdefend scan test-contracts/cosmwasm/cw-plus --chain cosmwasm
rustdefend scan test-contracts/near/near-sdk-rs --chain near
rustdefend scan test-contracts/ink/ink-examples --chain ink
```

## License

MIT
