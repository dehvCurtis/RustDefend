use quote::ToTokens;
use syn::visit::Visit;
use syn::ImplItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingPayableCheckDetector;

impl Detector for MissingPayableCheckDetector {
    fn id(&self) -> &'static str {
        "INK-010"
    }
    fn name(&self) -> &'static str {
        "ink-missing-payable-check"
    }
    fn description(&self) -> &'static str {
        "Detects non-payable #[ink(message)] methods that reference transferred_value()"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = PayableVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct PayableVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for PayableVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        // Check for #[ink(message)] attribute
        let mut has_ink_message = false;
        let mut is_payable = false;
        for attr in &method.attrs {
            let tokens = attr.meta.to_token_stream().to_string();
            if tokens.contains("ink") && tokens.contains("message") {
                has_ink_message = true;
                if tokens.contains("payable") {
                    is_payable = true;
                }
            }
        }

        if !has_ink_message || is_payable {
            return;
        }

        let body_src = method.block.to_token_stream().to_string();

        // Check if body references transferred_value
        if !body_src.contains("transferred_value") {
            return;
        }

        let fn_name = method.sig.ident.to_string();
        let line = span_to_line(&method.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "INK-010".to_string(),
            name: "ink-missing-payable-check".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            message: format!(
                "#[ink(message)] '{}' uses transferred_value() but is not marked payable",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&method.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Add `payable` to the ink attribute: `#[ink(message, payable)]` if the method should accept value transfers".to_string(),
            chain: Chain::Ink,
        });
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
            Chain::Ink,
            std::collections::HashMap::new(),
        );
        MissingPayableCheckDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_non_payable_with_transferred_value() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn deposit(&mut self) {
                    let value = self.env().transferred_value();
                    self.balance += value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect non-payable using transferred_value"
        );
    }

    #[test]
    fn test_no_finding_payable_method() {
        let source = r#"
            impl MyContract {
                #[ink(message, payable)]
                pub fn deposit(&mut self) {
                    let value = self.env().transferred_value();
                    self.balance += value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag payable method");
    }
}
