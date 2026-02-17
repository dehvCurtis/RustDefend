use syn::visit::Visit;
use syn::{ImplItemFn, Visibility};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingPrivateDetector;

impl Detector for MissingPrivateDetector {
    fn id(&self) -> &'static str {
        "NEAR-006"
    }
    fn name(&self) -> &'static str {
        "missing-private-callback"
    }
    fn description(&self) -> &'static str {
        "Detects public callback methods (on_* / *_callback) without #[private] attribute"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Near
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Require NEAR-specific source markers to avoid cross-chain FPs
        if !ctx.source.contains("near_sdk")
            && !ctx.source.contains("near_contract_standards")
            && !ctx.source.contains("#[near_bindgen]")
            && !ctx.source.contains("#[near(")
            && !ctx.source.contains("env::predecessor_account_id")
            && !ctx.source.contains("env::signer_account_id")
            && !ctx.source.contains("Promise::new")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = PrivateVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct PrivateVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for PrivateVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let fn_name = method.sig.ident.to_string();

        // Check if this looks like a callback
        let is_callback = fn_name.starts_with("on_")
            || fn_name.ends_with("_callback")
            || fn_name.starts_with("handle_")
            || fn_name.contains("callback");

        if !is_callback {
            return;
        }

        // Check if it's public
        let is_public = matches!(method.vis, Visibility::Public(_));
        if !is_public {
            return;
        }

        // Check for #[private] attribute
        let has_private = has_attribute(&method.attrs, "private");

        if !has_private {
            let line = span_to_line(&method.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "NEAR-006".to_string(),
                name: "missing-private-callback".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                message: format!(
                    "Callback method '{}' is public without #[private] attribute",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&method.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add #[private] attribute to ensure only the contract itself can call this callback".to_string(),
                chain: Chain::Near,
            });
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
            Chain::Near,
            std::collections::HashMap::new(),
        );
        MissingPrivateDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_private() {
        let source = r#"
            use near_sdk::env;
            #[near_bindgen]
            impl Contract {
                pub fn on_transfer_complete(&mut self, amount: U128) {
                    self.total += amount.0;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing #[private]");
    }

    #[test]
    fn test_no_finding_with_private() {
        let source = r#"
            impl Contract {
                #[private]
                pub fn on_transfer_complete(&mut self, amount: U128) {
                    self.total += amount.0;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with #[private]");
    }
}
