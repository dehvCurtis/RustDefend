# Task 4: New Detectors for 2024+ Threats

**Priority:** P2 (Coverage expansion)
**Estimated Effort:** Large
**Status:** Planned

## Summary

Add 9 new detectors targeting emerging 2024-2025 vulnerability classes. Total detector count: 32 -> 41.

---

## Solana Detectors

### SOL-010: Unsafe PDA Seed Construction
- **Severity:** High | **Confidence:** Medium
- **File:** `src/detectors/solana/unsafe_pda_seeds.rs`
- **Threat:** Predictable/mutable seeds enable PDA account collision attacks. Attackers can precompute addresses and front-run account creation.
- **Detection:** Flag `Pubkey::find_program_address()` or `create_program_address()` where seed arrays contain only string literals or constants without user-specific components (e.g., missing user pubkey in seeds).
- **Safe patterns to skip:** Seeds containing parameter references, `authority.key()`, `user.key()`, `mint.key()`
- **Complexity:** Medium (AST visitor, inspect function call arguments)

**Vulnerable:**
```rust
let (pda, bump) = Pubkey::find_program_address(&[b"vault"], program_id);
```

**Safe:**
```rust
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()], program_id
);
```

### SOL-011: Missing Rent-Exempt Check
- **Severity:** Medium | **Confidence:** Medium
- **File:** `src/detectors/solana/missing_rent_exempt.rs`
- **Threat:** Accounts created without rent-exemption can be garbage-collected by the runtime, causing data loss.
- **Detection:** Flag `create_account` or `system_instruction::create_account` calls where the function body doesn't reference `rent` or `Rent` or `minimum_balance`.
- **Safe patterns to skip:** Anchor's `init` constraint (handles automatically), functions containing `Rent::get()` or `rent.minimum_balance()`
- **Complexity:** Easy (source text pattern matching on function body)

---

## CosmWasm Detectors

### CW-008: Unsafe cosmwasm-std Version
- **Severity:** High | **Confidence:** High
- **File:** `src/detectors/cosmwasm/unsafe_version.rs`
- **Threat:** cosmwasm-std < 2.0.2 has CWA-2024-002 (CVE-2024-58263) — certain `Uint256::pow`/`Int256::neg` operations use wrapping math instead of panicking.
- **Detection:** Parse Cargo.toml for `cosmwasm-std` version. Flag if < 1.4.4 (for 1.x) or < 2.0.2 (for 2.x).
- **Safe patterns:** Version >= 2.0.2 or >= 1.5.4
- **Complexity:** Easy (Cargo.toml parsing, version comparison)
- **Note:** Requires new utility `src/utils/cargo_parser.rs` and Scanner extension to pass Cargo.toml to detectors.

**Vulnerable Cargo.toml:**
```toml
[dependencies]
cosmwasm-std = "1.4.0"
```

### CW-009: Missing Address Validation
- **Severity:** High | **Confidence:** Medium
- **File:** `src/detectors/cosmwasm/missing_address_validation.rs`
- **Threat:** Bech32 addresses without `addr_validate()` can have case variations that bypass storage key lookups (Halborn zero-day 2024).
- **Detection:** Flag `Addr::unchecked()` calls in non-test code. Flag functions that receive `String` address parameters and use them in storage operations without calling `deps.api.addr_validate()`.
- **Safe patterns:** `deps.api.addr_validate(&addr)?` before storage use, `Addr::unchecked()` in test code
- **Complexity:** Medium (AST visitor, track variable flow)

**Vulnerable:**
```rust
fn execute_transfer(deps: DepsMut, recipient: String) -> StdResult<Response> {
    let addr = Addr::unchecked(&recipient);
    BALANCES.save(deps.storage, &addr, &amount)?;
    Ok(Response::new())
}
```

**Safe:**
```rust
fn execute_transfer(deps: DepsMut, recipient: String) -> StdResult<Response> {
    let addr = deps.api.addr_validate(&recipient)?;
    BALANCES.save(deps.storage, &addr, &amount)?;
    Ok(Response::new())
}
```

---

## NEAR Detectors

### NEAR-009: Unsafe Storage Key Construction
- **Severity:** Medium | **Confidence:** Medium
- **File:** `src/detectors/near/unsafe_storage_keys.rs`
- **Threat:** Predictable storage keys (e.g., `format!("user_{}", user_input)`) can be collided by malicious actors to corrupt other users' data.
- **Detection:** Flag `env::storage_write` or `UnorderedMap::new()` / `LookupMap::new()` where the key/prefix is constructed from function parameters using `format!` or string concatenation.
- **Safe patterns:** Keys using `BorshSerialize`, `sha256`, or fixed prefixes with proper enum-based namespacing
- **Complexity:** Medium (AST + source pattern matching)

### NEAR-010: Missing Deposit Check
- **Severity:** High | **Confidence:** High
- **File:** `src/detectors/near/missing_deposit_check.rs`
- **Threat:** Functions accepting NEAR deposits without checking `env::attached_deposit()` can be called with 0 deposit, bypassing payment requirements.
- **Detection:** Flag `#[payable]` methods that don't reference `attached_deposit` in the body. Also flag storage registration functions (`storage_deposit`) without deposit validation.
- **Safe patterns:** Function body contains `env::attached_deposit()` with comparison/assert
- **Complexity:** Easy (attribute check + body text search)

**Vulnerable:**
```rust
#[payable]
pub fn purchase(&mut self, item_id: u64) {
    // Never checks attached_deposit!
    self.inventory.remove(&item_id);
    self.sold.insert(&item_id, &env::predecessor_account_id());
}
```

**Safe:**
```rust
#[payable]
pub fn purchase(&mut self, item_id: u64) {
    let deposit = env::attached_deposit();
    assert!(deposit >= self.prices.get(&item_id).unwrap(), "Insufficient payment");
    self.inventory.remove(&item_id);
}
```

---

## ink! Detectors

### INK-009: Unsafe Delegate Call
- **Severity:** Critical | **Confidence:** High
- **File:** `src/detectors/ink/unsafe_delegate_call.rs`
- **Threat:** `DelegateCall` to unverified contracts allows arbitrary code execution in the caller's storage context. The delegatee can modify any storage slot and drain funds.
- **Detection:** Flag `delegate_call` or `DelegateCall` usage where the target contract/code hash comes from function parameters or storage without whitelist verification.
- **Safe patterns:** Hardcoded code hash, `assert_eq!(code_hash, KNOWN_HASH)` before delegate
- **Complexity:** Medium (AST visitor, check call arguments)

**Vulnerable:**
```rust
#[ink(message)]
pub fn proxy_call(&mut self, target_hash: Hash, input: Vec<u8>) {
    ink::env::call::build_call::<Environment>()
        .delegate(target_hash)  // User-controlled!
        .exec_input(...)
        .fire();
}
```

### INK-010: Missing Payable Check
- **Severity:** Medium | **Confidence:** Medium
- **File:** `src/detectors/ink/missing_payable_check.rs`
- **Threat:** Non-payable messages that access `self.env().transferred_value()` may have confused semantics — the value check passes but the method wasn't designed to receive funds. ink! 5+ rejects value transfers to non-payable methods at runtime, but older versions may not.
- **Detection:** Flag methods NOT marked `payable` that reference `transferred_value()` in their body.
- **Safe patterns:** Method is marked `#[ink(message, payable)]`
- **Complexity:** Easy (attribute + body text search)

---

## Cross-Chain Detector

### DEP-001: Outdated Dependency Versions
- **Severity:** High | **Confidence:** High
- **File:** `src/detectors/common/outdated_deps.rs`
- **Threat:** Known-vulnerable SDK versions. Supply chain attacks and CVEs in core dependencies.
- **Detection:** Parse Cargo.toml for known-vulnerable version ranges:

| Crate | Vulnerable Versions | CVE/Advisory |
|-------|-------------------|--------------|
| `cosmwasm-std` | < 1.4.4, 1.5.0-1.5.3, 2.0.0-2.0.1 | CWA-2024-002 |
| `cosmwasm-vm` | < 1.5.8, 2.0.0-2.0.5 | CWA-2025-001 |
| `near-sdk` | < 4.0.0 | Legacy callback issues |
| `ink` | < 4.0.0 | Pre-reentrancy-default |
| `anchor-lang` | < 0.28.0 | Various account validation fixes |
| `solana-program` | < 1.16.0 | Various runtime fixes |

- **Safe patterns:** Version above minimum, git dependencies (can't check), workspace inheritance
- **Complexity:** Medium (Cargo.toml parsing, semver comparison, vulnerability database)
- **Note:** Requires `src/utils/cargo_parser.rs` utility and scanner extension

---

## Infrastructure Requirements

### New utility: `src/utils/cargo_parser.rs`
- Parse Cargo.toml with the `toml` crate (already a dependency)
- Extract dependency names and version specs
- Provide `parse_cargo_toml(path) -> HashMap<String, VersionSpec>`
- Handle version ranges, workspace inheritance, git deps

### Scanner extension
- In `src/scanner/mod.rs`, after detecting chains from Cargo.toml, also pass Cargo.toml data to detectors
- Option A: Add `cargo_toml: Option<toml::Value>` to `ScanContext`
- Option B: Run Cargo.toml-based detectors separately (one per project, not per file)
- Option B is cleaner — add a `detect_project(&self, cargo_toml: &Path) -> Vec<Finding>` method to Detector trait with default empty impl

### Registration
- Add new detectors to chain-specific `mod.rs` files
- Add `common/mod.rs` for cross-chain DEP-001
- Update `DetectorRegistry` to include common detectors

## Implementation Order

### Week 1: Easy detectors
1. **NEAR-010** (Missing Deposit Check) — Easy, high value
2. **INK-010** (Missing Payable Check) — Easy, similar pattern
3. **CW-008** (Unsafe Version) — Easy, requires cargo_parser utility

### Week 2: Medium AST detectors
4. **SOL-010** (Unsafe PDA Seeds) — Medium, important for Solana
5. **SOL-011** (Missing Rent-Exempt) — Medium, common issue
6. **CW-009** (Missing Address Validation) — Medium, 2024 zero-day
7. **NEAR-009** (Unsafe Storage Keys) — Medium

### Week 3: Complex detectors + integration
8. **INK-009** (Unsafe Delegate Call) — Medium, critical severity
9. **DEP-001** (Outdated Dependencies) — Medium, cross-chain
10. Scanner extension for Cargo.toml-based detectors

## Verification

- [ ] Each detector has 2+ test cases (vulnerable + safe)
- [ ] `cargo build` compiles
- [ ] `cargo test` — all tests pass (70 existing + ~20 new)
- [ ] `cargo run -- list-detectors` shows 41 detectors
- [ ] Re-scan test contracts with new detectors
- [ ] No regressions in existing 32 detectors
