# CosmWasm Detectors

13 detectors for CosmWasm smart contracts.

| ID | Name | Severity | Confidence |
|----|------|----------|------------|
| CW-001 | Integer overflow | Low | Low |
| CW-002 | Reentrancy (CEI violation, IBC/reply only) | Low | Low |
| CW-003 | Missing sender check | Critical | Medium |
| CW-004 | Storage prefix collision | High | High |
| CW-005 | Unchecked query response | High | Low |
| CW-006 | Improper error handling (panic in entry point) | High | High |
| CW-007 | Unbounded iteration | High | Medium |
| CW-008 | Unsafe IBC entry points | High | Medium |
| CW-009 | Missing address validation (`Addr::unchecked`) | High | Medium |
| CW-010 | Unguarded migrate entry | Medium | Medium |
| CW-011 | Missing reply ID validation | Medium | Medium |
| CW-012 | Sylvia pattern issues | Medium | Medium |
| CW-013 | CW2 migration issues | Medium | Medium |

---

## CW-001: cosmwasm-integer-overflow

- **Severity:** Low | **Confidence:** Low
- Detects unchecked arithmetic on `Uint128`/`Uint256` types.
- Low severity because CosmWasm's types panic on overflow (safe revert, not exploitable). Use `checked_*` for graceful error handling.
- Skips test/mock/helper functions.
- Skips test/mock file paths (`/testing/`, `/mock/`, `/testutils/`, `integration_tests/`, `multitest/`).

## CW-002: cosmwasm-reentrancy

- **Severity:** Low | **Confidence:** Low
- Detects storage writes (`.save()`) followed by `add_message()` / `add_submessage()` in IBC/reply handlers.
- Only flags IBC handlers, reply handlers, and SubMsg dispatchers — the only contexts where CosmWasm's non-reentrancy guarantee can be circumvented (CWA-2024-007).
- Non-IBC execute handlers are not flagged.

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

## CW-008: unsafe-ibc-entry-points

- **Severity:** High | **Confidence:** Medium
- Detects IBC packet handlers (`ibc_packet_receive`, `ibc_packet_ack`, `ibc_packet_timeout`, `ibc_source_callback`, `ibc_destination_callback`) without channel validation or proper timeout rollback.
- For receive/ack/callback handlers: checks for `channel_id` validation or `ALLOWED_CHANNEL`/`IBC_CHANNEL` constants.
- For timeout handlers: checks for rollback logic (`refund`, `rollback`, `revert`) or storage mutations (`.save()`, `.update()`, `.remove()`).
- Skips if `ibc_channel_open` in same file validates channels at connection time.

## CW-009: cosmwasm-missing-addr-validation

- **Severity:** High | **Confidence:** Medium
- Detects `Addr::unchecked()` usage in non-test code.
- Unvalidated addresses can have bech32 case variations that bypass storage key lookups.
- Use `deps.api.addr_validate()` instead.

## CW-010: unguarded-migrate-entry

- **Severity:** Medium | **Confidence:** Medium
- Detects `migrate` handler without admin/sender check or version validation.
- Checks for `info.sender` authorization patterns and `cw2::set_contract_version` / `get_contract_version` version validation.
- Skips trivial/stub implementations (less than 60 non-whitespace characters).

## CW-011: missing-reply-id-validation

- **Severity:** Medium | **Confidence:** Medium
- Detects `reply` handler not matching on `msg.id`, processing all submessage replies identically.
- Checks for `msg.id`, `reply.id`, `REPLY_ID`, `SubMsgResult`, `match msg`/`match reply` patterns.
- Skips trivial implementations (less than 50 non-whitespace characters).

## CW-012: sylvia-pattern-issues

- **Severity:** Medium | **Confidence:** Medium
- Detects `#[sv::msg(exec)]` methods in Sylvia contracts that write to storage without auth checks.
- Sylvia's macro system generates CosmWasm entry points from annotated methods; missing auth in exec methods exposes state mutations.
- Safe patterns: `info.sender` check, `ensure!`/`require!`/`assert!` with sender, `is_admin`/`is_owner` check.

## CW-013: cw2-migration-issues

- **Severity:** Medium | **Confidence:** Medium
- Detects cosmwasm-std 2.x API misuse: `from_binary`/`to_binary` deprecated in favor of `from_json`/`to_json_binary`.
- Using deprecated APIs may break on future cosmwasm-std updates.
- Also detects other 2.x migration patterns that may need updating.
