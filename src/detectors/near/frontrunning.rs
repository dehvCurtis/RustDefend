use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct FrontrunningDetector;

impl Detector for FrontrunningDetector {
    fn id(&self) -> &'static str {
        "NEAR-008"
    }
    fn name(&self) -> &'static str {
        "frontrunning-risk"
    }
    fn description(&self) -> &'static str {
        "Detects Promise::new().transfer() in functions that take user-provided parameters"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::Low
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
        let mut visitor = FrontrunVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct FrontrunVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for FrontrunVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Must have transfer via Promise
        if !body_src.contains(".transfer(") && !body_src.contains(". transfer (") {
            return;
        }

        if !body_src.contains("Promise") {
            return;
        }

        // Check if function has user-provided parameters (non-self)
        let has_user_params = func.sig.inputs.len() > 1; // more than &self

        if !has_user_params {
            return;
        }

        // Check for commit-reveal or nonce patterns
        let has_protection = body_src.contains("commit")
            || body_src.contains("reveal")
            || body_src.contains("nonce")
            || body_src.contains("deadline")
            || body_src.contains("block_timestamp");

        if !has_protection {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "NEAR-008".to_string(),
                name: "frontrunning-risk".to_string(),
                severity: Severity::High,
                confidence: Confidence::Low,
                message: format!(
                    "Function '{}' transfers tokens based on user parameters without frontrunning protection",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Consider implementing commit-reveal scheme, deadline parameter, or nonce to prevent frontrunning".to_string(),
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
        FrontrunningDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_frontrunning_risk() {
        let source = r#"
            use near_sdk::Promise;
            fn claim_reward(&mut self, amount: u128, recipient: AccountId) {
                Promise::new(recipient).transfer(amount);
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect frontrunning risk");
    }

    #[test]
    fn test_no_finding_with_deadline() {
        let source = r#"
            use near_sdk::{Promise, env};
            fn claim_reward(&mut self, amount: u128, recipient: AccountId, deadline: u64) {
                assert!(env::block_timestamp() < deadline, "Expired");
                Promise::new(recipient).transfer(amount);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with deadline protection"
        );
    }
}
