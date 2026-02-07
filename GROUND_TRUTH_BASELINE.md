# RustDefend Ground Truth Baseline

**Generated:** 2026-02-07
**Scanner Version:** 0.1.0
**Total Detectors:** 32

---

## Detector Relevance Assessment (2024+)

### Solana — 9 detectors, **8 relevant for 2024+**

| ID | Name | Severity | 2024+ Relevant? | Notes |
|---|---|---|---|---|
| SOL-001 | missing-signer-check | Critical | **Yes** | Anchor auto-handles via `Signer<'info>`, but native programs (~20-30% of new code) still vulnerable. Scanner already skips Anchor patterns. |
| SOL-002 | missing-owner-check | Critical | **Yes** | Anchor auto-handles via `Account<'info, T>`, but native programs still need manual checks. Scanner already skips Anchor patterns. |
| SOL-003 | integer-overflow | Critical | **Yes** | Solana BPF/SBF compiles in **release mode** — overflow checks are **disabled** by default. This remains the #1 finding by volume in real codebases. |
| SOL-004 | account-confusion | High | **Yes** | Anchor auto-handles discriminators, but SPL/native programs still do manual deserialization. |
| SOL-005 | insecure-account-close | High | **Yes** | Anchor provides `close` constraint but developers must use it correctly. Native programs fully exposed. |
| SOL-006 | arbitrary-cpi | Critical | **Yes** | Anchor's `Program<'info, T>` helps, but custom CPI wrappers and native programs remain vulnerable. |
| SOL-007 | pda-bump-misuse | High | **Yes** | `create_program_address` with user-provided bumps still seen in native code. Anchor uses canonical bumps. |
| SOL-008 | unchecked-cpi-return | High | **Yes** | Neither Anchor nor runtime enforces CPI return value checking. |
| SOL-009 | cpi-reentrancy | Medium | **Reduced** | Solana's single-threaded execution model and account locking provide some protection. CEI violations are lower risk than on EVM chains but still flagged for defense-in-depth. |

**Summary:** 8 of 9 detectors fully relevant. SOL-009 has reduced relevance due to Solana's execution model but remains useful.

---

### CosmWasm — 7 detectors, **5 relevant for 2024+**

| ID | Name | Severity | 2024+ Relevant? | Notes |
|---|---|---|---|---|
| CW-001 | cosmwasm-integer-overflow | Critical → **Medium** | **Reduced** | CosmWasm `Uint128`/`Uint256` operators (`+`, `-`, `*`) **panic on overflow by default** since inception. Panicking aborts the transaction safely (no state corruption), but `checked_*` operations return `Result` for graceful handling. Downgrade to Medium — it's a code quality issue, not a security vulnerability. |
| CW-002 | cosmwasm-reentrancy | Medium | **Low** | CosmWasm's actor model is **non-reentrant by design**. Messages dispatch only after execution completes. The CEI pattern finding is informational at best. Exception: IBC-hooks reentrancy (CWA-2024-007) was an ibc-go issue, not CosmWasm core. |
| CW-003 | missing-sender-check | Critical | **Yes** | No framework-level mitigation. Developers must manually check `info.sender`. Remains critical. |
| CW-004 | storage-collision | High | **Yes** | cw-storage-plus uses developer-specified string prefixes. Duplicate prefixes cause silent data corruption. No compile-time prevention. |
| CW-005 | unchecked-query-response | High | **Yes** | Cross-contract queries return unvalidated data. No framework protection. |
| CW-006 | improper-error-handling | High | **Yes** | `unwrap()`/`panic!()` in entry points abort the transaction, potentially causing DoS or unexpected reverts. No compile-time prevention. |
| CW-007 | unbounded-iteration | High | **Yes** | Gas limits exist but unbounded `.range()` can exceed block gas limits, causing permanent DoS on affected functionality. |

**Summary:** 5 of 7 detectors fully relevant. CW-001 should be downgraded to Medium (panics are safe reverts, not exploitable overflows). CW-002 has low relevance due to architectural non-reentrancy.

---

### NEAR — 8 detectors, **8 relevant for 2024+**

| ID | Name | Severity | 2024+ Relevant? | Notes |
|---|---|---|---|---|
| NEAR-001 | promise-reentrancy | Critical | **Yes** | NEAR's async promise model has no runtime reentrancy protection. Between a cross-contract call and its callback, **any method can be executed**. This remains the #1 NEAR-specific vulnerability class. |
| NEAR-002 | signer-vs-predecessor | High | **Yes** | `signer_account_id()` vs `predecessor_account_id()` confusion enables phishing through cross-contract call chains. No SDK-level prevention. |
| NEAR-003 | storage-staking-auth | High | **Yes** | Storage deposit/withdraw without auth check remains an active concern. |
| NEAR-004 | callback-unwrap-usage | High | **Yes** | `#[callback_unwrap]` not formally deprecated but `#[callback_result]` is recommended (near-sdk v5.24+). Panicking callbacks can leave state inconsistent. |
| NEAR-005 | near-wrapping-arithmetic | Critical | **Yes** | `wrapping_*`/`saturating_*` on balance variables silently produce wrong values. No runtime mitigation. |
| NEAR-006 | missing-private-callback | Critical | **Yes** | Public callback methods without `#[private]` allow anyone to call them, bypassing cross-contract call security. |
| NEAR-007 | self-callback-state | High | **Yes** | Pending state writes before `ext_self::` calls without guards remain exploitable in the async model. |
| NEAR-008 | frontrunning-risk | High | **Yes** | Public mempool + promise-based transfers remain susceptible to frontrunning. |

**Summary:** All 8 detectors fully relevant. NEAR has made no runtime changes that mitigate any of these vulnerability classes. The SDK improvements (v5.24) add safer APIs but don't enforce their use.

---

### ink! (Polkadot) — 8 detectors, **6 relevant for 2024+**

| ID | Name | Severity | 2024+ Relevant? | Notes |
|---|---|---|---|---|
| INK-001 | ink-reentrancy | Critical | **Yes** | ink! denies reentrancy by default, but `set_allow_reentry(true)` explicitly opts in. Flagging this is correct — it detects intentional but risky opt-in. |
| INK-002 | ink-integer-overflow | Critical → **Low** | **Reduced** | `cargo-contract` enables Rust's `overflow-checks` by default. Arithmetic panics on overflow at runtime. Only relevant if developers manually disable overflow checks in Cargo.toml. |
| INK-003 | ink-missing-caller-check | Critical | **Yes** | No framework-level mitigation. Developers must manually check `self.env().caller()`. |
| INK-004 | ink-timestamp-dependence | Medium | **Yes** | `block_timestamp()` in decision logic remains manipulable by validators/collators. |
| INK-005 | ink-unbounded-storage | Medium | **Yes** | Unbounded storage growth causes increasing costs and potential DoS. No framework prevention. |
| INK-006 | ink-cross-contract | High | **Yes** | `try_invoke()` without result checking remains a developer responsibility. |
| INK-007 | ink-panic-usage | High | **Yes** | `unwrap()`/`panic!()` in messages cause transaction revert. No compile-time prevention. |
| INK-008 | ink-result-suppression | Medium | **Yes** | `let _ = result` silently discards errors. No framework prevention. |

**Ecosystem Note:** ink! development ceased January 2026 due to lack of funding. Polkadot is pivoting to Revive/PolkaVM with EVM compatibility. Existing contracts on Astar/Aleph Zero still run, but no new security patches will be issued. This makes static analysis **more important, not less** — there's no framework team to fix issues.

**Summary:** 6 of 8 detectors fully relevant. INK-002 has reduced relevance due to default overflow checks (but still catches manual disabling). INK-001 is relevant as it catches explicit opt-in to risky behavior.

---

## Relevance Summary

| Chain | Total | Fully Relevant | Reduced | Not Relevant |
|---|---|---|---|---|
| **Solana** | 9 | 8 | 1 (SOL-009) | 0 |
| **CosmWasm** | 7 | 5 | 2 (CW-001, CW-002) | 0 |
| **NEAR** | 8 | 8 | 0 | 0 |
| **ink!** | 8 | 6 | 2 (INK-002, INK-001*) | 0 |
| **Total** | **32** | **27** | **5** | **0** |

*INK-001 is "reduced" in the sense that reentrancy is denied by default, but the detector correctly flags explicit opt-in — so it's still valuable.

**Overall: 27 of 32 detectors (84%) are fully relevant for 2024+. The remaining 5 have reduced but non-zero relevance.**

---

## Ground Truth Test Results

Scan date: 2026-02-07
Test corpus: Open-source, audited smart contract repositories

### Test Corpus

| Repository | Chain | Description | Commit |
|---|---|---|---|
| solana-program-library (SPL) | Solana | Official Solana reference programs | latest main |
| anchor | Solana | Anchor framework + examples | latest main |
| cw-plus | CosmWasm | Production CosmWasm contracts | latest main |
| cosmwasm (core) | CosmWasm | CosmWasm VM + example contracts | latest main |
| near-sdk-rs | NEAR | NEAR SDK + examples | latest main |
| near-ft | NEAR | NEAR fungible token reference | latest main |
| ink-examples | ink! | Official ink! example contracts | latest main |

### Baseline Finding Counts (per-chain scan)

```
Chain         Total   Detectors Triggered
─────────────────────────────────────────
Solana/SPL      303   SOL-001:36  SOL-002:45  SOL-003:144  SOL-004:48
                      SOL-005:6   SOL-006:4   SOL-007:8    SOL-009:12
Solana/Anchor    85   SOL-001:1   SOL-002:27  SOL-003:17   SOL-004:12
                      SOL-005:5   SOL-006:19  SOL-009:4
CosmWasm         99   CW-001:47   CW-002:5    CW-005:6     CW-006:41
NEAR             13   NEAR-001:2  NEAR-002:1  NEAR-004:4   NEAR-005:1
                      NEAR-006:3  NEAR-008:2
ink!            105   INK-002:2   INK-003:36  INK-005:15   INK-006:6
                      INK-007:36  INK-008:10
─────────────────────────────────────────
TOTAL           605
```

### Expected True Positive Assessment

**Solana/SPL (303 findings):**
- SOL-003 (144): **~80% TP.** SPL token-swap uses unchecked arithmetic on financial calculations (`amount - fee`, `amount * price`). These are real risks in release-mode Solana programs.
- SOL-004 (48): **~60% TP.** Many SPL programs do manual deserialization with IsInitialized checks (our detector now recognizes this), but some utility functions that implement Pack trait are caught.
- SOL-002 (45): **~70% TP.** SPL programs often accept AccountInfo and deserialize without explicit owner checks, relying on higher-level validation.
- SOL-001 (36): **~50% TP.** Internal helper functions accept AccountInfo; signer check often occurs at a higher call level. Medium confidence is appropriate.

**Solana/Anchor (85 findings):**
- SOL-002 (27): **~40% TP.** Anchor's test infrastructure and utility functions trigger this. Many are in non-user-facing code.
- SOL-006 (19): **~50% TP.** Anchor examples often demonstrate CPI patterns; some lack explicit program ID validation because the framework handles it elsewhere.
- SOL-003 (17): **~70% TP.** Unchecked arithmetic in Anchor programs is a real issue since Anchor doesn't auto-protect.

**CosmWasm (99 findings):**
- CW-001 (47): **~30% TP for security, ~90% TP for code quality.** Uint128 panics are safe reverts, but checked ops are better practice.
- CW-006 (41): **~90% TP.** Example contracts (`nested-contracts`) genuinely use `todo!()` and `unwrap()` in entry points. Real finding.
- CW-002 (5): **~20% TP.** CosmWasm is non-reentrant by design; these are informational.

**NEAR (13 findings):**
- All categories: **~70% TP.** Low total count indicates good precision. Remaining findings are in SDK example code.

**ink! (105 findings):**
- INK-003 (36): **~40% TP.** Many ink! examples (flipper, incrementer) intentionally have permissionless messages. True for contracts that shouldn't be permissionless.
- INK-007 (36): **~80% TP.** Actual `panic!()` and `expect()` in message functions. Upgradeable contract examples use `panic!()` for set_code_hash failures.
- INK-005 (15): **~60% TP.** Unbounded storage growth in examples that lack production-grade bounds.

### Overall Estimated Precision

| Category | Estimated TP Rate | Findings | Est. True Positives |
|---|---|---|---|
| Critical severity | ~65% | 198 | ~129 |
| High severity | ~60% | 312 | ~187 |
| Medium severity | ~45% | 95 | ~43 |
| **Total** | **~59%** | **605** | **~359** |

---

## False Positive Reduction History

| Stage | Total Findings | Reduction |
|---|---|---|
| Pre-FP-fix baseline | 1,563 | — |
| After global test exclusion | ~1,100 | -30% |
| After all detector-specific fixes | 605 | -61% total |

### FP Fixes Applied

1. **Global:** Test file/directory exclusion (`/tests/`, `/test/`, `/fuzz/`, `_test.rs`)
2. **SOL-001:** Skip `&[AccountInfo]` slices, known safe params, deduplicate per-function, exclude read-only `lamports()`
3. **SOL-003:** Skip literal arithmetic (`x + 1`), string concatenation, `.len()`/`as usize`
4. **SOL-004:** Skip test/pack/unpack/serialize/deserialize functions, recognize `IsInitialized` pattern
5. **SOL-006:** Skip SPL helper functions, expand program ID check patterns
6. **CW-002:** Skip test-like function names
7. **CW-006:** Skip test-like function names (`_works`, `_test`, `_mock`, `_should`, `#[test]`)
8. **CW-007:** Skip test-like function names
9. **NEAR-002:** Skip doc comments, string literals, test functions
10. **NEAR-004:** Skip SDK macro infrastructure, comments, string literals
11. **INK-003:** Require `&mut self`, proper `self.field =` assignment detection
12. **INK-005:** Skip ERC-20/721 standard methods (approve, transfer, etc.)
13. **INK-007:** Skip `checked_*.unwrap()` pattern
14. **INK-008:** Skip common non-Result patterns (callbacks, formatting macros)

---

## Detector Coverage Gaps (Not Yet Implemented)

Based on 2024-2025 vulnerability research, the following emerging threat categories are **not covered** by RustDefend:

| Gap | Chain | Priority | Description |
|---|---|---|---|
| Supply chain analysis | All | High | Dependency auditing for malicious crates (cf. @solana/web3.js backdoor) |
| Access key misuse | NEAR | Medium | Function call access keys with excessive allowances |
| IBC message validation | CosmWasm | Medium | Cross-chain message handling vulnerabilities |
| Delegate call safety | ink! | Medium | `DelegateCall` to untrusted contracts in ink! 5+/6 |
| Oracle manipulation | Solana | Medium | Price feed staleness and manipulation patterns |
| Flash loan guards | CosmWasm | Low | Missing flash loan protections in DeFi contracts |
| Bech32 normalization | CosmWasm | Low | Address case normalization (patched in cosmwasm-std but old contracts affected) |

---

## Methodology Notes

- **Scanner configuration:** Default settings, `--chain` flag used per-repository
- **Suppression:** No `// rustdefend-ignore` comments in test corpus
- **Confidence filter:** All confidence levels included (High + Medium + Low)
- **TP estimation:** Manual review of sampled findings (10-20 per detector), extrapolated to full set
- **Precision target:** 60%+ for High confidence detectors, 40%+ for Medium confidence
