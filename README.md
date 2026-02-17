# RustDefend

Static security scanner for Rust smart contracts. Analyzes source code via AST parsing (`syn` crate) to detect vulnerabilities across Solana, CosmWasm, NEAR, and ink! ecosystems.

- **50 detectors** covering the most common smart contract vulnerability classes
- **AST-based analysis** — parses Rust source into syntax trees, no regex pattern matching
- **Auto-detects chain** from `Cargo.toml` dependencies (solana-program, cosmwasm-std, near-sdk, ink)
- **Parallel file processing** via `rayon` for fast scans on large codebases
- **Multiple output formats** — colored text, JSON, SARIF v2.1.0

## Installation

### From source

Requires Rust 1.70+.

```bash
git clone https://github.com/BlockSecOps/RustDefend.git
cd RustDefend
cargo install --path .
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/BlockSecOps/RustDefend/releases). Available for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64).

## Usage

```bash
# Scan a project (chain auto-detected from Cargo.toml)
rustdefend scan /path/to/project

# Force a specific chain
rustdefend scan /path/to/project --chain solana

# Filter by severity and confidence
rustdefend scan . --severity critical,high
rustdefend scan . --confidence high

# Run specific detectors
rustdefend scan . --detector SOL-001,SOL-003

# Output formats
rustdefend scan . --format text    # colored terminal output (default)
rustdefend scan . --format json    # JSON array
rustdefend scan . --format sarif   # SARIF v2.1.0 for CI/CD

# List available detectors
rustdefend list-detectors
rustdefend list-detectors --chain near

# Quiet mode (exit code only: 0=clean, 1=findings)
rustdefend scan . --quiet
```

## Detectors

50 detectors across 4 chains + cross-chain dependency analysis:

| Chain | Count | Docs |
|-------|-------|------|
| Solana | 14 | [docs/detectors/solana/](docs/detectors/solana/) |
| CosmWasm | 11 | [docs/detectors/cosmwasm/](docs/detectors/cosmwasm/) |
| NEAR | 12 | [docs/detectors/near/](docs/detectors/near/) |
| ink! | 11 | [docs/detectors/ink/](docs/detectors/ink/) |
| Cross-chain | 2 | [docs/detectors/common/](docs/detectors/common/) |

See [docs/detectors/](docs/detectors/) for the full detector index and [all_detectors.json](docs/detectors/all_detectors.json) for machine-readable metadata.

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

## Inline Suppression

```rust
let total = amount + fee; // rustdefend-ignore
let total = amount + fee; // rustdefend-ignore[SOL-003]
```

- `rustdefend-ignore` suppresses all detectors for that line
- `rustdefend-ignore[ID]` suppresses a specific detector

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT
