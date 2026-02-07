# CosmWasm Detectors

## CW-001: cosmwasm-integer-overflow

- **Severity:** Medium | **Confidence:** Medium
- Detects unchecked arithmetic on `Uint128`/`Uint256` types.
- Medium severity because CosmWasm's types panic on overflow (safe revert, not exploitable). Use `checked_*` for graceful error handling.

## CW-002: cosmwasm-reentrancy

- **Severity:** Low | **Confidence:** Low
- Detects storage writes (`.save()`) followed by `add_message()` / `add_submessage()`.
- Informational only. CosmWasm's actor model is non-reentrant by design.

## CW-003: missing-sender-check

- **Severity:** Critical | **Confidence:** Medium
- Detects `ExecuteMsg` match arms that mutate storage without checking `info.sender`.

## CW-004: storage-collision

- **Severity:** High | **Confidence:** High
- Collects all `Map::new("prefix")` / `Item::new("prefix")` strings and flags duplicates.
- Duplicate prefixes cause data corruption.

## CW-005: unchecked-query-response

- **Severity:** High | **Confidence:** Low
- Detects `deps.querier.query()` results used without bounds or validity checks.

## CW-006: improper-error-handling

- **Severity:** High | **Confidence:** High
- Detects `unwrap()`, `expect()`, `panic!()` in `execute`, `instantiate`, `query`, `reply`, `migrate` entry points.
- These cause unrecoverable aborts instead of returning errors.

## CW-007: unbounded-iteration

- **Severity:** High | **Confidence:** Medium
- Detects `.range()` or `.iter()` without `.take()` in execute handlers.
- Unbounded iteration can hit gas limits.

## CW-009: cosmwasm-missing-addr-validation

- **Severity:** High | **Confidence:** Medium
- Detects `Addr::unchecked()` usage in non-test code.
- Unvalidated addresses can have bech32 case variations that bypass storage key lookups.
- Use `deps.api.addr_validate()` instead.
