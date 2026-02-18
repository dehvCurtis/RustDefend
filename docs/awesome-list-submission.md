# Awesome List Submissions

Formatted descriptions for submitting RustDefend to community curated lists.

---

## awesome-rust

**Category:** Development tools > Build system / Static analysis

```markdown
* [RustDefend](https://github.com/BlockSecOps/RustDefend) - Static security scanner for Rust smart contracts (Solana, CosmWasm, NEAR, ink!) with 61 detectors, AST-based analysis, SARIF output, and custom rules engine. [![CI](https://github.com/BlockSecOps/RustDefend/actions/workflows/ci.yml/badge.svg)](https://github.com/BlockSecOps/RustDefend/actions)
```

---

## awesome-solana-security

**Category:** Tools / Static Analysis

```markdown
* [RustDefend](https://github.com/BlockSecOps/RustDefend) - AST-based static security scanner for Solana programs (native + Anchor). 21 Solana-specific detectors covering missing signer/owner checks, integer overflow, account confusion, PDA misuse, CPI reentrancy, Token-2022 risks, and more. Supports SARIF output for CI/CD integration, intra-file call graph analysis, workspace-aware chain detection, baseline diff, and custom TOML-defined rules.
```

---

## awesome-cosmwasm

**Category:** Tools / Security

```markdown
* [RustDefend](https://github.com/BlockSecOps/RustDefend) - Static security scanner with 13 CosmWasm detectors: missing sender checks, storage collisions, reentrancy (IBC/reply), unbounded iteration, Addr::unchecked, CW2 migration issues, Sylvia patterns, and more. AST-based analysis via `syn` crate, SARIF output, custom rules engine.
```
