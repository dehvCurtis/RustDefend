# Cross-Chain Detectors

4 cross-chain detectors for dependency and build analysis.

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| DEP-001 | Outdated dependencies with known CVEs | High | High |
| DEP-002 | Supply chain risk indicators | High | High |
| DEP-003 | Build script abuse | Critical | Medium |
| DEP-004 | Proc-macro supply chain | High | Low |

---

## DEP-001: outdated-dependencies

- **Severity:** High | **Confidence:** High
- Parses `Cargo.toml` for known-vulnerable dependency versions.
- Checked crates and minimum safe versions:

| Crate | Vulnerable Versions | Advisory |
|-------|---------------------|----------|
| `cosmwasm-std` | < 1.4.4, 1.5.0-1.5.3, 2.0.0-2.0.1 | CWA-2024-002 / CVE-2024-58263 |
| `cosmwasm-vm` | < 1.5.8, 2.0.0-2.0.5 | CWA-2025-001 |
| `near-sdk` | < 4.0.0 | Legacy callback issues |
| `ink` | < 4.0.0 | Pre-reentrancy-default |
| `anchor-lang` | < 0.28.0 | Account validation fixes |
| `solana-program` | < 1.16.0 | Runtime fixes |

- Skips git and path dependencies (versions cannot be checked).

## DEP-002: supply-chain-risk

- **Severity:** High | **Confidence:** High
- Detects supply chain risk indicators in `Cargo.toml`:

### Wildcard Versions
- Version `"*"` or partial wildcards like `"1.*"`
- `">= 0"` or `"> 0"` (equivalent to wildcard)
- Allows any version including potentially malicious releases

### Unpinned Git Dependencies
- Git dependencies without `rev =` or `tag =`
- Mutable branch references can be silently replaced with malicious code
- Medium confidence (Cargo.lock pins in practice)

### Known Malicious Crate Names
- Exact-match detection of known typosquatting/supply chain attack crates:
  `rustdecimal`, `faster_log`, `async_println`, `finch-rust`, `finch-rst`, `sha-rust`, `sha-rst`, `finch_cli_rust`, `polymarket-clients-sdk`, `polymarket-client-sdks`
- High confidence (exact match only)

### False Positive Filters
- Skips `path =` dependencies (local, not supply chain risk)
- Skips `workspace = true` (inherited version)
- Skips `[dev-dependencies]` for wildcard detection (crates.io allows wildcards there)
- Git deps with `rev =` or `tag =` are considered pinned (safe)

## DEP-003: build-script-abuse

- **Severity:** Critical | **Confidence:** Medium
- Detects `build.rs` files with network downloads or arbitrary shell execution.
- Build scripts execute at compile time with full system access. Network-fetching build scripts can introduce supply chain attacks.
- Trigger patterns: `reqwest`, `curl`, `wget`, `hyper::Client`, `Command::new("curl")`, `Command::new("sh")`, `Command::new("bash")`.
- Also flags `fs::write` combined with `Command` (download-and-execute pattern).
- Only scans files named `build.rs`.

## DEP-004: proc-macro-supply-chain

- **Severity:** High | **Confidence:** Low
- Detects proc-macro dependencies with unpinned versions in `Cargo.toml`.
- Proc macros execute arbitrary code at compile time. Unpinned versions allow silent updates to potentially malicious releases.
- Checks for: wildcard versions (`*`), major-only versions (`"1"`), git deps without `rev` or `tag`.
- Proc-macro detection: crate names ending in `_derive`, `_macro`, `-derive`, `-macro`, or containing `proc-macro`/`proc_macro`.
- Skips `path =` dependencies and `workspace = true` (inherited versions).
