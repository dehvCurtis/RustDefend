use quote::ToTokens;
use syn::visit::Visit;
use syn::{BinOp, ExprBinary, ItemFn};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct IntegerOverflowDetector;

impl Detector for IntegerOverflowDetector {
    fn id(&self) -> &'static str {
        "INK-002"
    }
    fn name(&self) -> &'static str {
        "ink-integer-overflow"
    }
    fn description(&self) -> &'static str {
        "Detects unchecked arithmetic on Balance/u128 types (cargo-contract enables overflow-checks by default)"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Only fire on ink! contracts — check for ink-specific markers in source
        if !ctx.source.contains("#[ink(")
            && !ctx.source.contains("#[ink::")
            && !ctx.source.contains("ink_storage")
            && !ctx.source.contains("ink_env")
            && !ctx.source.contains("ink_lang")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = OverflowVisitor {
            findings: &mut findings,
            ctx,
            in_function: false,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct OverflowVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    in_function: bool,
}

impl<'ast, 'a> Visit<'ast> for OverflowVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Check if function signature mentions Balance type
        let fn_src = func.to_token_stream().to_string();
        if fn_src.contains("Balance") || fn_src.contains("u128") {
            self.in_function = true;
            syn::visit::visit_item_fn(self, func);
            self.in_function = false;
        }
    }

    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        if !self.in_function {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        let is_arithmetic = matches!(
            expr.op,
            BinOp::Add(_)
                | BinOp::Sub(_)
                | BinOp::Mul(_)
                | BinOp::AddAssign(_)
                | BinOp::SubAssign(_)
                | BinOp::MulAssign(_)
        );

        if !is_arithmetic {
            syn::visit::visit_expr_binary(self, expr);
            return;
        }

        // Skip literals
        if matches!(&*expr.left, syn::Expr::Lit(_)) && matches!(&*expr.right, syn::Expr::Lit(_)) {
            return;
        }

        let line = get_op_line(&expr.op);
        let snippet = snippet_at_line(&self.ctx.source, line);

        if !snippet.contains("checked_") && !snippet.contains("saturating_") {
            self.findings.push(Finding {
                detector_id: "INK-002".to_string(),
                name: "ink-integer-overflow".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                message: format!(
                    "Unchecked arithmetic on Balance/u128: {}",
                    expr.to_token_stream()
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: 1,
                snippet,
                recommendation: "cargo-contract enables overflow-checks by default (panics safely). Use checked_add(), checked_sub(), checked_mul() for graceful error handling. Only critical if overflow-checks manually disabled".to_string(),
                chain: Chain::Ink,
            });
        }

        syn::visit::visit_expr_binary(self, expr);
    }
}

fn get_op_line(op: &BinOp) -> usize {
    let span = match op {
        BinOp::Add(t) => t.span,
        BinOp::Sub(t) => t.span,
        BinOp::Mul(t) => t.span,
        BinOp::AddAssign(t) => t.spans[0],
        BinOp::SubAssign(t) => t.spans[0],
        BinOp::MulAssign(t) => t.spans[0],
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
            Chain::Ink,
            std::collections::HashMap::new(),
        );
        IntegerOverflowDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_balance_overflow() {
        let source = r#"
            // #[ink(message)]
            fn transfer(&mut self, amount: Balance) {
                self.total = self.total + amount;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect unchecked Balance arithmetic"
        );
    }

    #[test]
    fn test_no_finding_checked() {
        let source = r#"
            // #[ink(message)]
            fn transfer(&mut self, amount: Balance) -> Result<(), Error> {
                self.total = self.total.checked_add(amount).ok_or(Error::Overflow)?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag checked arithmetic");
    }
}
