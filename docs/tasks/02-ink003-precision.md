# Task 2: INK-003 Precision Improvement

**Priority:** P0 (Critical detector at 40% TP is unacceptable)
**Estimated Effort:** Medium
**Status:** DONE

## Problem

INK-003 (`ink-missing-caller-check`) is a **Critical** severity detector with only ~40% true positive rate. It flags every `#[ink(message)]` method with `&mut self` that writes storage without a caller check, but many methods are intentionally permissionless (e.g., `flip()`, `inc_by()`, `approve()`).

## Root Cause Analysis

The detector doesn't distinguish between:
1. **Admin operations** (writing to `self.owner`, `self.admin`, `self.config`) — always need caller check
2. **User-facing operations** (writing to caller-indexed mappings like allowances) — caller is implicit
3. **Permissionless utilities** (incrementing counters, toggling booleans) — by design

## Planned Improvements (in priority order)

### Phase 1: Quick wins (target 55-65% TP)

#### 1a. Payable method detection
- Methods marked `#[ink(message, payable)]` are designed as user entry points
- Downgrade to `Confidence::Low` instead of suppressing entirely
- Check for `payable` in the `#[ink(...)]` attribute token stream

#### 1b. Field-based risk scoring
- **High-risk writes** (always flag): fields containing `owner`, `admin`, `authority`, `manager`, `controller`, `paused`, `frozen`, `config`
- **Low-risk writes** (downgrade confidence): fields containing `count`, `value`, `total`, simple state toggles
- Extract the field name from `self.FIELD = ...` pattern already detected by `has_self_field_assignment()`

#### 1c. Value transfer detection
- Methods containing `self.env().transfer(` or `transferred_value` ALWAYS need caller checks regardless of other signals
- Keep these at Critical/High even when other heuristics suggest permissionless

### Phase 2: Semantic analysis (target 65-75% TP)

#### 2a. Caller-scoped assignment detection
- Detect `mapping.insert(&self.env().caller(), ...)` or `mapping.insert(&caller, ...)` where caller was assigned from `self.env().caller()`
- These are inherently caller-scoped — the caller IS the auth
- Example: ERC-20 `approve()` writes `allowances[caller][spender] = value`

#### 2b. Method name heuristics
- Likely admin: `set_owner`, `set_admin`, `configure`, `initialize`, `pause`, `freeze`, `withdraw_all`, `drain`
- Likely permissionless: `flip`, `inc`, `inc_by`, `vote`, `bid`, `deposit`
- Use name patterns to adjust confidence, not to suppress

### Phase 3: Polish (target 75%+ TP)

#### 3a. Return type error analysis
- Methods returning `Result<_, InsufficientBalance>` or similar have implicit access control via business logic
- Detect common error enum variants that imply authorization

## Implementation Details

**File:** `src/detectors/ink/missing_caller_check.rs`

Key changes to the `visit_impl_item_fn` method:
1. After detecting `has_ink_attr` and `&mut self`, extract additional signals
2. Add `is_payable` check from attribute tokens
3. Add `get_written_field_names()` helper that extracts field names from `self.X = ...`
4. Add `has_value_transfer()` check for `transfer(` in body
5. Add `is_caller_scoped_write()` check for mapping inserts keyed by caller
6. Use signals to select severity/confidence:
   - Value transfer without check: Critical / High
   - Admin field write without check: Critical / Medium
   - General write without check: High / Medium (downgrade from Critical)
   - Payable or caller-scoped write: Medium / Low

## Test Cases to Add

```rust
// Should flag (TP): admin field write
#[ink(message)]
pub fn set_owner(&mut self, new_owner: AccountId) {
    self.owner = new_owner;  // Critical without caller check!
}

// Should NOT flag (FP fix): payable user-facing
#[ink(message, payable)]
pub fn deposit(&mut self) {
    self.deposits.insert(&self.env().caller(), &self.env().transferred_value());
}

// Should NOT flag (FP fix): caller-scoped mapping write
#[ink(message)]
pub fn approve(&mut self, spender: AccountId, value: Balance) {
    let owner = self.env().caller();
    self.allowances.insert((&owner, &spender), &value);
}

// Should flag (TP): value transfer without auth
#[ink(message)]
pub fn drain(&mut self, to: AccountId) {
    self.env().transfer(to, self.env().balance()).unwrap();
}
```

## Expected Impact

| Phase | TP Rate | FP Rate | Findings Affected |
|-------|---------|---------|-------------------|
| Current | ~40% | ~60% | 36 |
| After Phase 1 | ~60% | ~40% | ~22 (14 suppressed/downgraded) |
| After Phase 2 | ~72% | ~28% | ~15 |
| After Phase 3 | ~78% | ~22% | ~12 |

## Verification

- [x] Existing 3 test cases still pass
- [x] New test cases added
- [x] Re-scan ink-examples: Critical findings reduced, remaining ones are true admin issues
- [x] No false negatives introduced for `set_owner`, `drain`, `withdraw` type methods
