# RustDefend VS Code Extension

VS Code integration for [RustDefend](https://github.com/BlockSecOps/RustDefend), a static security scanner for Rust smart contracts.

## Prerequisites

Install `rustdefend`:

```bash
cargo install rustdefend
```

## Usage

1. Open a Rust project with a `Cargo.toml`
2. Run `RustDefend: Scan Project` from the command palette (`Ctrl+Shift+P`)
3. Findings appear as diagnostics in the Problems panel and inline in the editor

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `rustdefend.binaryPath` | `rustdefend` | Path to the rustdefend binary |
| `rustdefend.scanOnSave` | `false` | Automatically scan on file save |
| `rustdefend.extraArgs` | `[]` | Extra CLI arguments (e.g., `["--chain", "solana"]`) |

## Development

```bash
cd vscode-extension
npm install
npm run compile
```

Press `F5` in VS Code to launch a development Extension Host.
