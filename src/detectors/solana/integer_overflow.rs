use quote::ToTokens;
use syn::visit::Visit;
use syn::{BinOp, Expr, ExprBinary, ImplItemFn, ItemFn};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct IntegerOverflowDetector;

impl Detector for IntegerOverflowDetector {
    fn id(&self) -> &'static str {
        "SOL-003"
    }
    fn name(&self) -> &'static str {
        "integer-overflow"
    }
    fn description(&self) -> &'static str {
        "Detects unchecked arithmetic operations on integer types"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = OverflowVisitor {
            findings: &mut findings,
            ctx,
            in_function: false,
            current_fn_name: String::new(),
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct OverflowVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    in_function: bool,
    current_fn_name: String,
}

impl<'ast, 'a> Visit<'ast> for OverflowVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip serialization/pack functions (bounded offset arithmetic)
        if is_pack_fn(&fn_name) {
            return;
        }

        // Skip test functions
        if is_test_fn(&fn_name, &func.attrs) {
            return;
        }

        let body_src = fn_body_source(func);
        // Skip if function exclusively uses checked arithmetic
        if !body_src.contains('+')
            && !body_src.contains('-')
            && !body_src.contains('*')
            && !body_src.contains('/')
        {
            return;
        }

        self.in_function = true;
        self.current_fn_name = fn_name;
        syn::visit::visit_item_fn(self, func);
        self.in_function = false;
        self.current_fn_name.clear();
    }

    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let fn_name = method.sig.ident.to_string();

        // Skip serialization/pack functions
        if is_pack_fn(&fn_name) {
            return;
        }

        // Skip test functions
        if is_test_fn(&fn_name, &method.attrs) {
            return;
        }

        let body_src = method.block.to_token_stream().to_string();
        if !body_src.contains('+')
            && !body_src.contains('-')
            && !body_src.contains('*')
            && !body_src.contains('/')
        {
            return;
        }

        self.in_function = true;
        self.current_fn_name = fn_name;
        syn::visit::visit_impl_item_fn(self, method);
        self.in_function = false;
        self.current_fn_name.clear();
    }

    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        if !self.in_function {
            return;
        }

        let is_arithmetic = matches!(
            expr.op,
            BinOp::Add(_)
                | BinOp::Sub(_)
                | BinOp::Mul(_)
                | BinOp::Div(_)
                | BinOp::AddAssign(_)
                | BinOp::SubAssign(_)
                | BinOp::MulAssign(_)
                | BinOp::DivAssign(_)
        );

        if !is_arithmetic {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        // Skip if both sides are literals (constant folding is safe)
        if is_literal(&expr.left) && is_literal(&expr.right) {
            return;
        }

        // Skip if either side is a literal (e.g., x + 1, slot + 1)
        // These are low risk and produce many false positives
        if is_literal(&expr.left) || is_literal(&expr.right) {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        let line = span_to_line(&expr.op.span());
        let snippet = snippet_at_line(&self.ctx.source, line);

        // Check if the line uses checked_* methods
        if snippet.contains("checked_")
            || snippet.contains("saturating_")
            || snippet.contains("wrapping_")
        {
            return;
        }

        // Skip string concatenation (+ on strings, common FP)
        let expr_str = expr.to_token_stream().to_string();
        if expr_str.contains("to_owned")
            || expr_str.contains("to_string")
            || expr_str.contains("String")
            || expr_str.contains("str")
            || expr_str.contains("format")
            || snippet.contains("as_bytes")
            || snippet.contains("to_owned")
            || snippet.contains("String")
        {
            return;
        }

        // Skip if adding to array index or len-like calls (low risk)
        if snippet.contains(".len()") || snippet.contains("as usize") {
            return;
        }

        // Skip widening casts: (a as u128) * (b as u128) is safe
        if is_widening_cast(&expr.left) && is_widening_cast(&expr.right) {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        // Skip if either operand involves a saturating_* call (already clamped)
        if expr_str.contains("saturating_") {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        // Division cannot overflow (only divide-by-zero) — use Low confidence
        let is_division = matches!(expr.op, BinOp::Div(_) | BinOp::DivAssign(_));
        let confidence = if is_division {
            Confidence::Low
        } else {
            Confidence::Medium
        };

        self.findings.push(Finding {
            detector_id: "SOL-003".to_string(),
            name: "integer-overflow".to_string(),
            severity: Severity::Critical,
            confidence,
            message: format!(
                "Unchecked arithmetic operation: {}",
                expr.to_token_stream().to_string()
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&expr.op.span()),
            snippet,
            recommendation: "Use checked_add(), checked_sub(), checked_mul(), or checked_div() to prevent overflow/underflow".to_string(),
            chain: Chain::Solana,
        });

        syn::visit::visit_expr_binary(self, expr);
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(_))
}

/// Check if expression is a widening cast like `(x as u128)` or `x as u64`
fn is_widening_cast(expr: &Expr) -> bool {
    match expr {
        Expr::Cast(cast) => {
            let ty_str = cast.ty.to_token_stream().to_string();
            ty_str == "u128" || ty_str == "i128" || ty_str == "u64" || ty_str == "i64"
        }
        Expr::Paren(paren) => is_widening_cast(&paren.expr),
        _ => {
            // Also check token stream for "as u128" pattern as fallback
            let s = expr.to_token_stream().to_string();
            s.contains("as u128") || s.contains("as i128")
        }
    }
}

/// Check if function name indicates a Pack/serialization impl
fn is_pack_fn(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "pack_into_slice"
        || n == "unpack_from_slice"
        || n == "pack"
        || n == "unpack"
        || n == "serialize"
        || n == "deserialize"
        || n == "try_from_slice"
        || n.starts_with("pack_")
        || n.starts_with("unpack_")
}

/// Check if function is a test
fn is_test_fn(name: &str, attrs: &[syn::Attribute]) -> bool {
    let n = name.to_lowercase();
    if n.starts_with("test_") || n.ends_with("_test") || n.contains("_works") {
        return true;
    }
    has_attribute(attrs, "test")
}

use proc_macro2::Span;

trait SpanExt {
    fn span(&self) -> Span;
}

impl SpanExt for BinOp {
    fn span(&self) -> Span {
        match self {
            BinOp::Add(t) => t.span,
            BinOp::Sub(t) => t.span,
            BinOp::Mul(t) => t.span,
            BinOp::Div(t) => t.span,
            BinOp::AddAssign(t) => t.spans[0],
            BinOp::SubAssign(t) => t.spans[0],
            BinOp::MulAssign(t) => t.spans[0],
            BinOp::DivAssign(t) => t.spans[0],
            _ => Span::call_site(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_detector(source: &str) -> Vec<Finding> {
        let ast = syn::parse_file(source).unwrap();
        let ctx = ScanContext::new(
            std::path::PathBuf::from("test.rs"),
            source.to_string(),
            ast,
            Chain::Solana,
        );
        IntegerOverflowDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unchecked_arithmetic() {
        let source = r#"
            fn transfer(amount: u64, fee: u64) -> u64 {
                let total = amount + fee;
                total
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unchecked arithmetic");
    }

    #[test]
    fn test_no_finding_for_string_concat() {
        let source = r#"
            fn build_name(prefix: String, suffix: &str) -> String {
                let result = prefix.to_owned() + suffix;
                result
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag string concatenation");
    }

    #[test]
    fn test_no_finding_literal_add() {
        let source = r#"
            fn next_slot(slot: u64) -> u64 {
                let next = slot + 1;
                next
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag adding a literal constant"
        );
    }

    #[test]
    fn test_no_finding_for_literals() {
        let source = r#"
            fn constants() -> u64 {
                let x = 1 + 2;
                x
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag literal arithmetic");
    }

    #[test]
    fn test_no_finding_widening_cast() {
        let source = r#"
            fn safe_multiply(a: u64, b: u64) -> u128 {
                let result = (a as u128) * (b as u128);
                result
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag widening cast multiplication"
        );
    }

    #[test]
    fn test_no_finding_pack_fn() {
        let source = r#"
            fn pack_into_slice(&self, dst: &mut [u8]) {
                let offset = start + size;
                dst[offset] = self.value;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag pack/serialization functions"
        );
    }

    #[test]
    fn test_division_low_confidence() {
        let source = r#"
            fn compute_share(amount: u64, total: u64) -> u64 {
                let share = amount / total;
                share
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should still detect division");
        assert_eq!(
            findings[0].confidence,
            Confidence::Low,
            "Division should have Low confidence"
        );
    }
}
