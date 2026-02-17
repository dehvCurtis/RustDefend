# Test Fixtures

Intentionally vulnerable smart contract code for testing RustDefend detectors that have zero findings in the main test corpus.

These fixtures are **not compilable contracts** — they are syntactically valid Rust files that trigger specific detector patterns via AST analysis.

## Coverage

| Fixture | Detector | Pattern |
|---------|----------|---------|
| `solana/unchecked_cpi.rs` | SOL-008 | `let _ = invoke(...)` without error handling |
| `solana/token2022_unsafe.rs` | SOL-012 | Token-2022 `InterfaceAccount`/`transfer_checked` without extension check |
| `solana/remaining_accounts_unsafe.rs` | SOL-013 | `ctx.remaining_accounts` without owner/type validation |
| `solana/init_if_needed_unsafe.rs` | SOL-014 | `init_if_needed` without reinitialization guard |
| `cosmwasm/missing_sender.rs` | CW-003 | `execute_*` mutates storage without `info.sender` check |
| `cosmwasm/storage_collision.rs` | CW-004 | Duplicate `Map::new("config")` / `Item::new("config")` |
| `cosmwasm/unbounded_iteration.rs` | CW-007 | `.range()` without `.take()` in execute handler |
| `cosmwasm/unsafe_ibc.rs` | CW-008 | IBC handlers without channel validation or timeout rollback |
| `near/storage_no_auth.rs` | NEAR-003 | `storage_deposit` without `predecessor_account_id` |
| `near/unguarded_pending.rs` | NEAR-007 | `self.pending_*` write before `ext_self::` without guard |
| `near/unsafe_storage_key.rs` | NEAR-009 | `format!()` key with `storage_write`/`storage_read` |
| `ink/allow_reentry.rs` | INK-001 | `set_allow_reentry(true)` |
| `ink/timestamp_compare.rs` | INK-004 | `block_timestamp()` in `if`/comparison/arithmetic |
| `ink/unsafe_delegate.rs` | INK-009 | `delegate(code_hash)` with user-controlled `Hash` param |
| `Cargo.toml` | DEP-001 | Outdated dependency versions with known CVEs |
| `Cargo.toml` | DEP-002 | Wildcard versions, malicious crate names, unpinned git deps |

## Running

```bash
# Scan all fixtures
rustdefend scan test-fixtures/solana --chain solana
rustdefend scan test-fixtures/cosmwasm --chain cosmwasm
rustdefend scan test-fixtures/near --chain near
rustdefend scan test-fixtures/ink --chain ink
rustdefend scan test-fixtures --chain solana  # triggers DEP-001 and DEP-002 via Cargo.toml
```
