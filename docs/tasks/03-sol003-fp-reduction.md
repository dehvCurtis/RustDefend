# Task 3: SOL-003 False Positive Reduction

**Priority:** P1 (Highest volume detector, 161 findings)
**Estimated Effort:** Medium-Large
**Status:** DONE

## Problem

SOL-003 (`integer-overflow`) generates 161 findings on SPL+Anchor — the most of any detector. Estimated ~80% TP rate means ~32 false positives. The remaining FPs fall into identifiable patterns.

## Current Filters (already implemented)

- Skip literal-only arithmetic (`1 + 2`)
- Skip literal + variable ops (`slot + 1`)
- Skip string concatenation (`.to_owned()`, `String`, `format`)
- Skip `.len()` / `as usize` patterns
- Skip lines containing `checked_*` / `saturating_*` / `wrapping_*`

## Planned Improvements

### Phase 1: High confidence, easy implementation

#### 1. Division confidence reduction
- **Pattern:** `BinOp::Div` and `BinOp::DivAssign`
- **Reason:** Integer division CANNOT overflow. `a / b` always produces result `<= a`. Only risk is divide-by-zero, which is a different bug class.
- **Change:** Report division with `Confidence::Low` instead of `Confidence::Medium`
- **Estimated FP reduction:** 12-15 findings
- **Risk of false negatives:** None (mathematically impossible)

#### 2. Cast-to-wider-type detection
- **Pattern:** `(a as u128) * (b as u128)` where both sides cast to wider type
- **Reason:** Developer explicitly widened to prevent overflow. `u64 * u64` fits in `u128`.
- **Change:** Skip when both operands are `Expr::Cast` to a wider integer type
- **Estimated FP reduction:** 15-20 findings
- **Risk of false negatives:** Very low — intentional widening is always safe

#### 3. Skip saturating arithmetic chains
- **Pattern:** `x.saturating_add(y) + z` where one operand is a `saturating_*` call
- **Reason:** Saturating result is already clamped to max
- **Change:** Check if either operand's token stream contains `saturating_`
- **Estimated FP reduction:** 4-6 findings
- **Risk of false negatives:** Very low

### Phase 2: Moderate complexity

#### 4. Skip Pack/serialization implementations
- **Pattern:** Arithmetic inside `impl Pack for T { ... }` blocks
- **Reason:** Pack implementations do array offset arithmetic that's bounded by struct layout
- **Change:** Track when inside `impl` block where trait path contains `Pack`, skip arithmetic
- **Note:** Current detector only visits `ItemFn` (free functions). Need to also consider `ImplItemFn` context or check function names like `pack_into_slice`, `unpack_from_slice`
- **Estimated FP reduction:** 8-12 findings
- **Risk of false negatives:** Very low — serialization code isn't where overflow bugs live

#### 5. Percentage/basis points pattern
- **Pattern:** `value * rate / DENOMINATOR` where denominator is a known constant (100, 1000, 10000)
- **Reason:** Bounded calculation — result is always <= value
- **Change:** When flagging a multiply, check if the next operation on the same expression is division by a literal >= 2
- **Estimated FP reduction:** 10-15 findings
- **Risk of false negatives:** Low-medium (dynamic divisors could be 0)

### Phase 3: Complex analysis

#### 6. Guarded arithmetic detection
- **Pattern:** Arithmetic preceded by a bounds check: `if amount <= balance { balance - amount }`
- **Reason:** The guard prevents the overflow condition
- **Change:** For subtraction specifically, scan preceding statements for `<=` / `<` comparisons on the same variables
- **Implementation:** Conservative — only handle the most common pattern: `if a <= b { b - a }`
- **Estimated FP reduction:** 10-18 findings
- **Risk of false negatives:** Medium (complex conditions hard to analyze statically)

## Implementation Details

**File:** `src/detectors/solana/integer_overflow.rs`

### For improvement #1 (division):
```
In visit_expr_binary, after confirming is_arithmetic:
- Check if op is BinOp::Div or BinOp::DivAssign
- If so, set confidence to Low instead of Medium in the Finding
```

### For improvement #2 (wider casts):
```
Add helper: fn is_widening_cast(expr: &Expr) -> bool
- Check if Expr::Cast where the target type is wider than expected source
- e.g., "as u128", "as u64", "as i128" in the token stream
In visit_expr_binary:
- If both left and right are widening casts, skip
```

### For improvement #4 (Pack impls):
```
Add state to OverflowVisitor: in_pack_impl: bool
Add visit_item_impl to detect trait path containing "Pack"
Set in_pack_impl = true during traversal, skip arithmetic
```

## Expected Impact

| Improvement | FP Eliminated | Cumulative TP Rate |
|---|---|---|
| Current baseline | 0 | ~80% |
| + Division confidence | 12-15 | ~83% |
| + Wider casts | 15-20 | ~88% |
| + Saturating chains | 4-6 | ~89% |
| + Pack impls | 8-12 | ~92% |
| + Percentage patterns | 10-15 | ~94% |
| + Guarded arithmetic | 10-18 | ~96% |
| **Total** | **59-86** | **~93-96%** |

## Test Cases to Add

```rust
// Should NOT flag: widening cast
fn safe_multiply(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

// Should NOT flag (or Low confidence): division
fn compute_share(amount: u64, total: u64) -> u64 {
    amount / total
}

// Should NOT flag: percentage calculation
fn compute_fee(amount: u64) -> u64 {
    amount * 3 / 10000
}

// Should still flag: unchecked multiply on same-width types
fn risky_multiply(a: u64, b: u64) -> u64 {
    a * b
}
```

## Verification

- [x] Existing 4 test cases still pass
- [x] New test cases added
- [x] Re-scan SPL: SOL-003 findings reduced from 488 to 131 (73% reduction)
- [x] No false negatives on known overflow patterns (`amount + fee`, `a * b`)
- [x] `cargo test` passes (95 tests)
