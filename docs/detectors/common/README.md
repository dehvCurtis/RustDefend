# Cross-Chain Detectors

1 cross-chain detector for dependency analysis.

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| DEP-001 | Outdated dependencies with known CVEs | High | High |

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
