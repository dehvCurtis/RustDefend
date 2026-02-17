use quote::ToTokens;
use syn::visit::Visit;
use syn::ImplItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnguardedSetCodeHashDetector;

impl Detector for UnguardedSetCodeHashDetector {
    fn id(&self) -> &'static str {
        "INK-011"
    }
    fn name(&self) -> &'static str {
        "unguarded-set-code-hash"
    }
    fn description(&self) -> &'static str {
        "Detects set_code_hash usage without admin/owner verification"
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
        let mut visitor = SetCodeHashVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const AUTH_PATTERNS: &[&str] = &[
    "caller",
    "admin",
    "owner",
    "ADMIN",
    "OWNER",
    "is_admin",
    "is_owner",
    "only_owner",
    "only_admin",
    "ensure_owner",
    "assert_eq !",
    "assert_eq!",
];

struct SetCodeHashVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SetCodeHashVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let body_src = method.block.to_token_stream().to_string();

        if !body_src.contains("set_code_hash") {
            return;
        }

        let fn_name = method.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_") || fn_name.ends_with("_test") {
            return;
        }

        let has_auth = AUTH_PATTERNS.iter().any(|p| body_src.contains(p));

        if !has_auth {
            let line = span_to_line(&method.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "INK-011".to_string(),
                name: "unguarded-set-code-hash".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Method '{}' calls set_code_hash without admin/owner verification",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&method.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add caller verification (e.g., assert_eq!(self.env().caller(), self.owner)) before set_code_hash to prevent unauthorized contract upgrades".to_string(),
                chain: Chain::Ink,
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
            Chain::Ink,
        );
        UnguardedSetCodeHashDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unguarded_set_code_hash() {
        let source = r#"
            impl MyContract {
                pub fn upgrade(&mut self, new_code_hash: Hash) {
                    self.env().set_code_hash(&new_code_hash).expect("upgrade failed");
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect unguarded set_code_hash"
        );
        assert_eq!(findings[0].detector_id, "INK-011");
    }

    #[test]
    fn test_no_finding_with_owner_check() {
        let source = r#"
            impl MyContract {
                pub fn upgrade(&mut self, new_code_hash: Hash) {
                    let caller = self.env().caller();
                    assert_eq!(caller, self.owner, "only owner can upgrade");
                    self.env().set_code_hash(&new_code_hash).expect("upgrade failed");
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with owner/caller check"
        );
    }

    #[test]
    fn test_no_finding_with_admin_guard() {
        let source = r#"
            impl MyContract {
                pub fn upgrade(&mut self, new_code_hash: Hash) {
                    self.ensure_owner();
                    self.env().set_code_hash(&new_code_hash).expect("upgrade failed");
                }
            }
        "#;
        // ensure_owner doesn't match our patterns, but "owner" substring does
        // Actually let me check - "ensure_owner" contains "owner"
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with admin guard method"
        );
    }
}
