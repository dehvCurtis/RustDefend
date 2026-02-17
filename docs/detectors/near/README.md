# NEAR Detectors

10 detectors for NEAR smart contracts.

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| NEAR-001 | Promise reentrancy | Critical | Medium |
| NEAR-002 | Signer vs predecessor confusion | High | High |
| NEAR-003 | Storage staking auth bypass | High | Medium |
| NEAR-004 | Callback unwrap usage | High | High |
| NEAR-005 | Wrapping arithmetic on balances | Critical | Medium |
| NEAR-006 | Missing #[private] on callback | Critical | High |
| NEAR-007 | Self-callback state inconsistency | High | Medium |
| NEAR-008 | Frontrunning risk | High | Low |
| NEAR-009 | Unsafe storage keys | Medium | Medium |
| NEAR-010 | Missing deposit check on #[payable] | High | High |

---

## NEAR-001: promise-reentrancy

- **Severity:** Critical | **Confidence:** Medium
- Detects state mutation (`self.field = ...`) before `Promise::new()` / `ext_*::` calls without a `#[private]` callback guard.

## NEAR-002: signer-vs-predecessor

- **Severity:** High | **Confidence:** High
- Detects `env::signer_account_id()` used in access control assertions.
- Should use `env::predecessor_account_id()` instead (signer can differ from caller in cross-contract calls).

## NEAR-003: storage-staking-auth

- **Severity:** High | **Confidence:** Medium
- Detects `storage_deposit` / `storage_withdraw` handlers without `predecessor_account_id()` check.

## NEAR-004: callback-unwrap-usage

- **Severity:** High | **Confidence:** High
- Detects `#[callback_unwrap]` attribute usage.
- Should use `#[callback_result]` with `Result` for proper error handling.

## NEAR-005: near-wrapping-arithmetic

- **Severity:** Critical | **Confidence:** Medium
- Detects `wrapping_*` / `saturating_*` on balance/amount variables.
- These silently mask overflow instead of failing.

## NEAR-006: missing-private-callback

- **Severity:** Critical | **Confidence:** High
- Detects public methods named `on_*` or `*_callback` without `#[private]` attribute.
- Without `#[private]`, anyone can call the callback directly.

## NEAR-007: self-callback-state

- **Severity:** High | **Confidence:** Medium
- Detects `pending_*` field writes before `ext_self::` calls without guard checks.

## NEAR-008: frontrunning-risk

- **Severity:** High | **Confidence:** Low
- Detects `Promise::new().transfer()` in functions that take user-provided parameters without commit-reveal patterns.

## NEAR-009: unsafe-storage-keys

- **Severity:** Medium | **Confidence:** Medium
- Detects storage key construction from user input via `format!()`.
- Predictable keys risk collision attacks. Use `BorshSerialize` or enum-based namespacing.

## NEAR-010: missing-deposit-check

- **Severity:** High | **Confidence:** High
- Detects `#[payable]` methods that don't reference `env::attached_deposit()`.
- Without a deposit check, the method can be called with zero payment.
