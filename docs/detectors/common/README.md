# Cross-Chain Detectors

2 cross-chain detectors for dependency analysis.

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| DEP-001 | Outdated dependencies with known CVEs | High | High |
| DEP-002 | Supply chain risk indicators | High | High |

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
