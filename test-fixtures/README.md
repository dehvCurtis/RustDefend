# Test Fixtures

Intentionally vulnerable smart contract code for testing RustDefend detectors.

These fixtures are **not compilable contracts** — they are syntactically valid Rust files that trigger specific detector patterns via AST analysis.

## Sources

- **Original fixtures**: Minimal pattern triggers for detectors with zero findings in the main test corpus
- **vulnerable-smart-contract-examples**: Real-world vulnerable Solana patterns from [BlockSecOps/vulnerable-smart-contract-examples](https://github.com/BlockSecOps/vulnerable-smart-contract-examples)

## Coverage

**All 50 detectors** have fixture coverage producing **159 total findings**.

### Solana Fixtures (67 findings, 14/14 detectors)

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `solana/missing_signer_vuln.rs` | SOL-001 | `AccountInfo` params without `is_signer` check |
| `solana/arithmetic_errors.rs` | SOL-002, SOL-003, SOL-004, SOL-005 | Unchecked arithmetic, missing discriminator/owner |
| `solana/missing_signer_check.rs` | SOL-003, SOL-005 | Missing signer, insecure close |
| `solana/missing_owner_check.rs` | SOL-002, SOL-003, SOL-004, SOL-005 | Missing `account.owner == program_id` |
| `solana/type_confusion.rs` | SOL-003, SOL-004 | Missing discriminator, type confusion |
| `solana/arbitrary_cpi.rs` | SOL-006 | User-controlled CPI target |
| `solana/pda_issues.rs` | SOL-003, SOL-004, SOL-007 | User-provided bump seeds |
| `solana/unchecked_cpi.rs` | SOL-008 | `let _ = invoke(...)` without error handling |
| `solana/cpi_reentrancy_vuln.rs` | SOL-009 | State mutation after CPI (CEI violation) |
| `solana/unsafe_pda_vuln.rs` | SOL-010 | PDA with static-only seeds |
| `solana/missing_rent_vuln.rs` | SOL-011 | `create_account` without rent check |
| `solana/token2022_unsafe.rs` | SOL-012 | Token-2022 without extension check |
| `solana/remaining_accounts_unsafe.rs` | SOL-013 | `remaining_accounts` without validation |
| `solana/init_if_needed_unsafe.rs` | SOL-014 | `init_if_needed` without guard |
| `solana/reinitialization.rs` | SOL-003, SOL-004, SOL-005 | Missing initialization check |
| `solana/rent_exemption.rs` | SOL-003, SOL-004, SOL-005 | Missing rent exemption |
| `solana/account_data_matching.rs` | SOL-002, SOL-003, SOL-004, SOL-005 | Missing account relationship validation |

### CosmWasm Fixtures (19 findings, 11/11 detectors)

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `cosmwasm/reentrancy_vuln.rs` | CW-001, CW-002 | `.save()` before `add_message()` (CEI violation) |
| `cosmwasm/missing_sender.rs` | CW-003 | `execute_*` without `info.sender` check |
| `cosmwasm/storage_collision.rs` | CW-004 | Duplicate storage prefixes |
| `cosmwasm/unchecked_query_vuln.rs` | CW-005 | Query response without validation |
| `cosmwasm/missing_reply_id.rs` | CW-006, CW-011 | `unwrap()` in entry point, no `msg.id` match |
| `cosmwasm/unbounded_iteration.rs` | CW-007 | `.range()` without `.take()` |
| `cosmwasm/unsafe_ibc.rs` | CW-008 | IBC handlers without channel validation |
| `cosmwasm/unchecked_addr_vuln.rs` | CW-009 | `Addr::unchecked()` in non-test code |
| `cosmwasm/unguarded_migrate.rs` | CW-010 | `migrate` without admin/version check |

### NEAR Fixtures (34 findings, 12/12 detectors)

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `near/unguarded_pending.rs` | NEAR-001, NEAR-007 | State mutation before `ext_self::` |
| `near/signer_confusion_vuln.rs` | NEAR-002 | `signer_account_id()` in access control |
| `near/storage_no_auth.rs` | NEAR-003, NEAR-012 | Storage handler without predecessor check |
| `near/callback_unwrap_vuln.rs` | NEAR-004 | `#[callback_unwrap]` usage |
| `near/wrapping_arithmetic_vuln.rs` | NEAR-005 | `wrapping_*`/`saturating_*` on balances |
| `near/missing_private_vuln.rs` | NEAR-006 | Public `on_*` methods without `#[private]` |
| `near/frontrunning_vuln.rs` | NEAR-008 | `Promise::new().transfer()` with user params |
| `near/unsafe_storage_key.rs` | NEAR-009 | `format!()` storage key construction |
| `near/missing_deposit_vuln.rs` | NEAR-010 | `#[payable]` without `attached_deposit()` |
| `near/unguarded_storage_unregister.rs` | NEAR-011 | `storage_unregister` without balance check |
| `near/missing_gas_callback.rs` | NEAR-012 | Cross-contract calls without gas spec |

### ink! Fixtures (30 findings, 11/11 detectors)

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `ink/allow_reentry.rs` | INK-001, INK-005, INK-010 | `set_allow_reentry(true)`, unbounded storage |
| `ink/integer_overflow_vuln.rs` | INK-002 | Unchecked `Balance`/`u128` arithmetic |
| `ink/missing_caller_vuln.rs` | INK-003 | `#[ink(message)]` writing storage without caller check |
| `ink/timestamp_compare.rs` | INK-004, INK-007 | `block_timestamp()` in comparison, panic in message |
| `ink/unchecked_invoke_vuln.rs` | INK-006 | `try_invoke()` without result check |
| `ink/result_suppression_vuln.rs` | INK-008 | `let _ = transfer(...)` suppressing Result |
| `ink/unsafe_delegate.rs` | INK-009 | `delegate_call` with user-controlled hash |
| `ink/unguarded_set_code_hash.rs` | INK-011 | `set_code_hash` without admin verification |

### Cross-chain Fixtures (9 findings, 2/2 detectors)

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `Cargo.toml` | DEP-001, DEP-002 | Outdated deps, wildcard versions, malicious crates |

## Baseline Finding Counts

```
Chain       Total  Detectors Triggered
────────────────────────────────────────────────────────
Solana        67   SOL-001:2  SOL-002:6  SOL-003:22  SOL-004:10
                   SOL-005:9  SOL-006:3  SOL-007:1   SOL-008:2
                   SOL-009:2  SOL-010:2  SOL-011:2   SOL-012:2
                   SOL-013:2  SOL-014:2
CosmWasm      19   CW-001:2   CW-002:2   CW-003:1    CW-004:2
                   CW-005:1   CW-006:1   CW-007:2    CW-008:3
                   CW-009:2   CW-010:2   CW-011:1
NEAR          34   NEAR-001:4 NEAR-002:2 NEAR-003:3  NEAR-004:2
                   NEAR-005:4 NEAR-006:3 NEAR-007:2  NEAR-008:3
                   NEAR-009:2 NEAR-010:2 NEAR-011:1  NEAR-012:6
ink!          30   INK-001:2  INK-002:3  INK-003:6   INK-004:3
                   INK-005:2  INK-006:3  INK-007:3   INK-008:2
                   INK-009:2  INK-010:2  INK-011:2
DEP            9   DEP-001:6  DEP-002:3
────────────────────────────────────────────────────────
TOTAL        159   50/50 detectors covered
```

## Running

```bash
# Scan all fixtures
rustdefend scan test-fixtures/solana --chain solana
rustdefend scan test-fixtures/cosmwasm --chain cosmwasm
rustdefend scan test-fixtures/near --chain near
rustdefend scan test-fixtures/ink --chain ink
rustdefend scan test-fixtures --chain solana  # triggers DEP-001 and DEP-002 via Cargo.toml
```
