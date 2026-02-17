use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnguardedStorageUnregisterDetector;

impl Detector for UnguardedStorageUnregisterDetector {
    fn id(&self) -> &'static str {
        "NEAR-011"
    }
    fn name(&self) -> &'static str {
        "unguarded-storage-unregister"
    }
    fn description(&self) -> &'static str {
        "Detects storage_unregister without checking non-zero token balances"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Near
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = StorageUnregisterVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const BALANCE_CHECK_PATTERNS: &[&str] = &[
    "balance",
    "amount",
    "is_empty",
    "== 0",
    "!= 0",
    "> 0",
    "is_zero",
    "non_zero",
    "nonzero",
    "has_balance",
    "tokens",
    "force",
];

struct StorageUnregisterVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for StorageUnregisterVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        if !fn_name.contains("storage_unregister") {
            return;
        }

        // Skip test functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let body_src = fn_body_source(func);

        let has_balance_check = BALANCE_CHECK_PATTERNS.iter().any(|p| body_src.contains(p));

        if !has_balance_check {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "NEAR-011".to_string(),
                name: "unguarded-storage-unregister".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Storage unregister handler '{}' does not check for non-zero token balances before removing account",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Check that the account has zero token balance before allowing storage_unregister, or require a 'force' parameter to acknowledge token loss".to_string(),
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
        UnguardedStorageUnregisterDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unguarded_unregister() {
        let source = r#"
            fn storage_unregister(&mut self) -> bool {
                let account_id = env::predecessor_account_id();
                self.accounts.remove(&account_id);
                env::storage_remove(&account_id.as_bytes());
                true
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect unguarded storage_unregister"
        );
        assert_eq!(findings[0].detector_id, "NEAR-011");
    }

    #[test]
    fn test_no_finding_with_balance_check() {
        let source = r#"
            fn storage_unregister(&mut self, force: Option<bool>) -> bool {
                let account_id = env::predecessor_account_id();
                let balance = self.internal_unwrap_balance_of(&account_id);
                if balance != 0 && !force.unwrap_or(false) {
                    env::panic_str("account has non-zero balance, use force=true to unregister");
                }
                self.accounts.remove(&account_id);
                true
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with balance check");
    }

    #[test]
    fn test_no_finding_with_force_param() {
        let source = r#"
            fn storage_unregister(&mut self, force: Option<bool>) -> bool {
                let account_id = env::predecessor_account_id();
                if !force.unwrap_or(false) {
                    return false;
                }
                self.accounts.remove(&account_id);
                true
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when force parameter is checked"
        );
    }
}
