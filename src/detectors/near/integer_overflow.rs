use quote::ToTokens;
use syn::visit::Visit;
use syn::{ExprMethodCall, ItemFn};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct IntegerOverflowDetector;

impl Detector for IntegerOverflowDetector {
    fn id(&self) -> &'static str {
        "NEAR-005"
    }
    fn name(&self) -> &'static str {
        "near-wrapping-arithmetic"
    }
    fn description(&self) -> &'static str {
        "Detects wrapping_*/saturating_* on balance/amount variables"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Near
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
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
        self.in_function = true;
        syn::visit::visit_item_fn(self, func);
        self.in_function = false;
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if !self.in_function {
            syn::visit::visit_expr_method_call(self, call);
            return;
        }

        let method = call.method.to_string();

        // Flag wrapping_* and saturating_* operations on financial values
        if method.starts_with("wrapping_") || method.starts_with("saturating_") {
            let expr_str = call.to_token_stream().to_string();

            // Check if this involves balance/amount/token related variables
            let is_financial = expr_str.contains("balance")
                || expr_str.contains("amount")
                || expr_str.contains("deposit")
                || expr_str.contains("stake")
                || expr_str.contains("token")
                || expr_str.contains("reward");

            if is_financial {
                let line = span_to_line(&call.method.span());
                self.findings.push(Finding {
                    detector_id: "NEAR-005".to_string(),
                    name: "near-wrapping-arithmetic".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Medium,
                    message: format!(
                        "{}() used on financial value - may silently lose precision",
                        method
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&call.method.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Use checked_* arithmetic and handle overflow explicitly for financial calculations".to_string(),
                    chain: Chain::Near,
                });
            }
        }

        syn::visit::visit_expr_method_call(self, call);
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
            Chain::Near,
        );
        IntegerOverflowDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_wrapping_on_balance() {
        let source = r#"
            fn update_balance(&mut self, amount: u128) {
                self.balance = self.balance.wrapping_add(amount);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect wrapping_add on balance"
        );
    }

    #[test]
    fn test_no_finding_checked() {
        let source = r#"
            fn update_balance(&mut self, amount: u128) -> Option<u128> {
                self.balance.checked_add(amount)
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag checked_add");
    }
}
