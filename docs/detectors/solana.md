# Solana Detectors

## SOL-001: missing-signer-check

- **Severity:** Critical | **Confidence:** High
- Detects functions accepting `AccountInfo` without verifying `is_signer`.
- Anchor's `Signer<'info>` type is recognized as safe.

## SOL-002: missing-owner-check

- **Severity:** Critical | **Confidence:** High
- Detects deserialization of account data (`try_from_slice`, `deserialize`) without verifying `account.owner == program_id`.
- Anchor's `Account<'info, T>` type is recognized as safe.

## SOL-003: integer-overflow

- **Severity:** Critical | **Confidence:** Medium
- Detects unchecked `+`, `-`, `*`, `/` operations on integer types.
- Solana BPF compiles in release mode with no overflow protection.
- Skips: literals, string concatenation, widening casts (`a as u128`), `checked_*`/`saturating_*`/`wrapping_*` calls, pack/serialization functions.
- Division reported at Low confidence (cannot overflow, only divide-by-zero).

## SOL-004: account-confusion

- **Severity:** High | **Confidence:** Medium
- Detects manual account deserialization without 8-byte discriminator check.
- Anchor accounts handle this automatically.

## SOL-005: insecure-account-close

- **Severity:** High | **Confidence:** Medium
- Detects account closure that zeros lamports but doesn't zero data and set discriminator.
- Anchor's `close = recipient` constraint is recognized as safe.

## SOL-006: arbitrary-cpi

- **Severity:** Critical | **Confidence:** Medium
- Detects `invoke()` or `CpiContext::new()` where the program target comes from untrusted input rather than a hardcoded `Program<'info, T>`.

## SOL-007: pda-bump-misuse

- **Severity:** High | **Confidence:** High
- Detects `create_program_address()` with user-provided bump seeds.
- `find_program_address()` is safe (derives canonical bump).

## SOL-008: unchecked-cpi-return

- **Severity:** High | **Confidence:** High
- Detects `let _ = invoke(...)` or CPI calls without `?` operator.

## SOL-009: cpi-reentrancy

- **Severity:** Medium | **Confidence:** Low
- Detects state mutations after CPI calls (CEI violation).
- Low confidence because Solana's account locking mitigates reentrancy.

## SOL-010: unsafe-pda-seeds

- **Severity:** High | **Confidence:** Medium
- Detects `find_program_address` / `create_program_address` with only static seeds (no user-specific components like `user.key()`).
- Static seeds risk PDA collision attacks.

## SOL-011: missing-rent-exempt

- **Severity:** Medium | **Confidence:** Medium
- Detects `create_account` calls without `Rent::get()` or `minimum_balance` checks.
- Accounts without rent exemption can be garbage-collected.
