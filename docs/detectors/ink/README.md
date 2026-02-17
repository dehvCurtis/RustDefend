# ink! Detectors

10 detectors for ink! smart contracts.

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| INK-001 | Reentrancy (allow_reentry) | Critical | High |
| INK-002 | Integer overflow | Low | Medium |
| INK-003 | Missing caller check | Critical | Medium |
| INK-004 | Timestamp dependence | Medium | Medium |
| INK-005 | Unbounded storage growth | Medium | Medium |
| INK-006 | Unchecked cross-contract call | High | High |
| INK-007 | Panic in message/constructor | High | High |
| INK-008 | Result suppression (`let _ =`) | Medium | Medium |
| INK-009 | Unsafe delegate call | Critical | High |
| INK-010 | Missing payable check | Medium | Medium |

---

## INK-001: ink-reentrancy

- **Severity:** Critical | **Confidence:** High
- Detects `set_allow_reentry(true)` anywhere in source.
- ink! defaults to `allow_reentry(false)`. Enabling it opens reentrancy attacks.

## INK-002: ink-integer-overflow

- **Severity:** Low | **Confidence:** Medium
- Detects unchecked arithmetic on `Balance` / `u128` types.
- Low severity because `cargo-contract` enables `overflow-checks` by default (panics safely). Use `checked_*` for graceful error handling.

## INK-003: ink-missing-caller-check

- **Severity:** Critical | **Confidence:** Medium
- Detects `#[ink(message)]` functions with `&mut self` that write storage without verifying `self.env().caller()`.
- Risk-stratified: Critical for sensitive fields (owner/admin/authority), High for general writes, Medium/Low for payable or caller-scoped writes.

## INK-004: ink-timestamp-dependence

- **Severity:** Medium | **Confidence:** Medium
- Detects `block_timestamp()` usage in comparison or arithmetic expressions.
- Block timestamps are manipulable by validators.

## INK-005: ink-unbounded-storage

- **Severity:** Medium | **Confidence:** Medium
- Detects `.push()` on `Vec` or `.insert()` on `Mapping` without a preceding length check.
- Unbounded growth can exhaust storage.

## INK-006: ink-cross-contract

- **Severity:** High | **Confidence:** High
- Detects `try_invoke()` without `?` or match on result.
- Unchecked cross-contract calls silently swallow errors.

## INK-007: ink-panic-usage

- **Severity:** High | **Confidence:** High
- Detects `unwrap()`, `expect()`, `panic!()` inside `#[ink(message)]` or `#[ink(constructor)]` functions.

## INK-008: ink-result-suppression

- **Severity:** Medium | **Confidence:** Medium
- Detects `let _ = expr` where `expr` returns `Result`.
- Silently suppressing errors can mask failures.

## INK-009: ink-unsafe-delegate-call

- **Severity:** Critical | **Confidence:** High
- Detects `delegate_call` with user-controlled code hash parameter.
- Unverified delegate calls allow arbitrary code execution in the caller's storage context.

## INK-010: ink-missing-payable-check

- **Severity:** Medium | **Confidence:** Medium
- Detects non-payable `#[ink(message)]` methods that reference `transferred_value()`.
- If a method uses `transferred_value()`, it should be marked `payable`.
