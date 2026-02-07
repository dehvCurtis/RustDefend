# RustDefend

Static security scanner for Rust smart contracts. Analyzes source code via AST parsing to detect vulnerabilities across Solana, CosmWasm, NEAR, and ink! ecosystems.

## Installation

### From source

Requires Rust 1.70+.

```bash
git clone https://github.com/user/rustdefend.git
cd rustdefend
cargo install --path .
```

### Build only

```bash
cargo build --release
```

Binary is at `target/release/rustdefend`.

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

40 detectors across 4 chains:

| Chain | Count | IDs |
|-------|-------|-----|
| Solana | 11 | SOL-001 through SOL-011 |
| CosmWasm | 8 | CW-001 through CW-009 |
| NEAR | 10 | NEAR-001 through NEAR-010 |
| ink! | 10 | INK-001 through INK-010 |
| Cross-chain | 1 | DEP-001 |

See [docs/detectors/](docs/detectors/) for details on each detector.

## Inline suppression

Suppress findings with comments:

```rust
let total = amount + fee; // rustdefend-ignore
let total = amount + fee; // rustdefend-ignore[SOL-003]
```

## Running tests

```bash
cargo test
```

## License

MIT
