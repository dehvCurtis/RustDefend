use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct StorageStakingDetector;

impl Detector for StorageStakingDetector {
    fn id(&self) -> &'static str {
        "NEAR-003"
    }
    fn name(&self) -> &'static str {
        "storage-staking-auth"
    }
    fn description(&self) -> &'static str {
        "Detects storage_deposit/storage_withdraw without predecessor_account_id check"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Near
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = StorageVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct StorageVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for StorageVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Only check storage-related handlers
        if !fn_name.contains("storage_deposit")
            && !fn_name.contains("storage_withdraw")
            && !fn_name.contains("storage_unregister")
        {
            return;
        }

        let body_src = fn_body_source(func);

        let has_predecessor_check = body_src.contains("predecessor_account_id");

        if !has_predecessor_check {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "NEAR-003".to_string(),
                name: "storage-staking-auth".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Storage handler '{}' does not check predecessor_account_id",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Use env::predecessor_account_id() to identify the caller and validate authorization".to_string(),
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
        StorageStakingDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_auth() {
        let source = r#"
            fn storage_withdraw(&mut self, amount: Option<U128>) -> bool {
                self.internal_storage_withdraw(amount.map(|a| a.0));
                true
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect missing predecessor check"
        );
    }

    #[test]
    fn test_no_finding_with_auth() {
        let source = r#"
            fn storage_withdraw(&mut self, amount: Option<U128>) -> bool {
                let account_id = env::predecessor_account_id();
                self.internal_storage_withdraw(&account_id, amount.map(|a| a.0));
                true
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with predecessor check"
        );
    }
}
