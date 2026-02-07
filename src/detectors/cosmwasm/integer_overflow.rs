use syn::visit::Visit;
use syn::{BinOp, ExprBinary, ItemFn};
use quote::ToTokens;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct IntegerOverflowDetector;

impl Detector for IntegerOverflowDetector {
    fn id(&self) -> &'static str { "CW-001" }
    fn name(&self) -> &'static str { "cosmwasm-integer-overflow" }
    fn description(&self) -> &'static str {
        "Detects unchecked arithmetic on Uint128/Uint256 types (panics safely but checked_* enables graceful handling)"
    }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn chain(&self) -> Chain { Chain::CosmWasm }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = OverflowVisitor {
            findings: &mut findings,
            ctx,
            in_uint_fn: false,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct OverflowVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    in_uint_fn: bool,
}

impl<'ast, 'a> Visit<'ast> for OverflowVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_src = func.to_token_stream().to_string();
        // Check if function signature involves Uint128/Uint256 types
        let involves_uint = fn_src.contains("Uint128") || fn_src.contains("Uint256")
            || fn_src.contains("uint128") || fn_src.contains("uint256");
        if involves_uint {
            self.in_uint_fn = true;
            syn::visit::visit_item_fn(self, func);
            self.in_uint_fn = false;
        }
    }

    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        if !self.in_uint_fn {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        let is_arithmetic = matches!(
            expr.op,
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_)
        );

        if !is_arithmetic {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        // Skip literal-only expressions
        if matches!(&*expr.left, syn::Expr::Lit(_)) && matches!(&*expr.right, syn::Expr::Lit(_)) {
            return;
        }

        let line = get_expr_line(expr);
        let snippet = snippet_at_line(&self.ctx.source, line);

        if !snippet.contains("checked_") {
            let expr_str = expr.to_token_stream().to_string();
            self.findings.push(Finding {
                detector_id: "CW-001".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Unchecked arithmetic on Uint128/Uint256: {}",
                    expr_str
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: 1,
                snippet,
                recommendation: "Uint128/Uint256 operators panic on overflow (safe revert). Use checked_add(), checked_sub(), checked_mul() for graceful error handling instead of panics".to_string(),
                chain: Chain::CosmWasm,
            });
        }

        syn::visit::visit_expr_binary(self, expr);
    }
}

fn get_expr_line(expr: &ExprBinary) -> usize {
    let span = match &expr.op {
        BinOp::Add(t) => t.span,
        BinOp::Sub(t) => t.span,
        BinOp::Mul(t) => t.span,
        BinOp::Div(t) => t.span,
        _ => proc_macro2::Span::call_site(),
    };
    span_to_line(&span)
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
            Chain::CosmWasm,
        );
        IntegerOverflowDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_uint128_overflow() {
        let source = r#"
            fn add_amounts(a: Uint128, b: Uint128) -> Uint128 {
                a + b
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unchecked Uint128 arithmetic");
    }

    #[test]
    fn test_no_finding_checked() {
        let source = r#"
            fn add_amounts(a: Uint128, b: Uint128) -> StdResult<Uint128> {
                a.checked_add(b)
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag checked arithmetic");
    }
}
