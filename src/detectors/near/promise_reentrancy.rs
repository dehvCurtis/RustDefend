use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct PromiseReentrancyDetector;

impl Detector for PromiseReentrancyDetector {
    fn id(&self) -> &'static str {
        "NEAR-001"
    }
    fn name(&self) -> &'static str {
        "promise-reentrancy"
    }
    fn description(&self) -> &'static str {
        "Detects state mutation before Promise::new() / ext_* calls without #[private] callback"
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
        let mut visitor = ReentrancyVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ReentrancyVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ReentrancyVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Must have Promise or ext_ calls
        let has_promise = body_src.contains("Promise :: new")
            || body_src.contains("Promise::new")
            || body_src.contains("ext_");

        if !has_promise {
            return;
        }

        // Check for self.field = ... pattern before promise
        let stmts = &func.block.stmts;
        let mut seen_state_mutation = false;

        for stmt in stmts {
            let stmt_str = stmt.to_token_stream().to_string();

            // State mutation patterns
            if stmt_str.contains("self .")
                && stmt_str.contains('=')
                && !stmt_str.contains("==")
                && !stmt_str.contains("!=")
            {
                seen_state_mutation = true;
            }

            // Promise after state mutation
            if seen_state_mutation
                && (stmt_str.contains("Promise :: new")
                    || stmt_str.contains("Promise::new")
                    || stmt_str.contains("ext_"))
            {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "NEAR-001".to_string(),
                    name: "promise-reentrancy".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Medium,
                    message: format!(
                        "Function '{}' mutates state before creating a Promise (reentrancy risk)",
                        func.sig.ident
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Move state mutations to a #[private] callback that executes after the Promise resolves, or use a guard pattern".to_string(),
                    chain: Chain::Near,
                });
                return;
            }
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
        PromiseReentrancyDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_state_before_promise() {
        let source = r#"
            fn withdraw(&mut self, amount: u128) {
                self.balance -= amount;
                Promise::new(receiver).transfer(amount);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect state mutation before Promise"
        );
    }

    #[test]
    fn test_no_finding_promise_only() {
        let source = r#"
            fn transfer(&self, receiver: AccountId, amount: u128) {
                Promise::new(receiver).transfer(amount);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when no state mutation"
        );
    }
}
