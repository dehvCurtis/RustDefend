use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct SignerVsPredecessorDetector;

impl Detector for SignerVsPredecessorDetector {
    fn id(&self) -> &'static str { "NEAR-002" }
    fn name(&self) -> &'static str { "signer-vs-predecessor" }
    fn description(&self) -> &'static str {
        "Detects env::signer_account_id() misuse in access control (should use predecessor)"
    }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn chain(&self) -> Chain { Chain::Near }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = SignerVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct SignerVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SignerVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Look for signer_account_id usage in assertions/comparisons
        if !body_src.contains("signer_account_id") {
            return;
        }

        // Skip functions that are tests or doc-test helpers
        let fn_name = func.sig.ident.to_string();
        if fn_name.contains("test") || has_attribute(&func.attrs, "test") {
            return;
        }

        // Verify signer_account_id appears in actual code, not just doc comments
        // by checking the function body source (which excludes doc comments)
        // Also skip if signer_account_id is only in string literals (logging, error messages)
        let in_code = body_src.lines().any(|line| {
            let trimmed = line.trim();
            // Skip comment lines
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*") {
                return false;
            }
            // Check if signer_account_id appears outside of string literals
            if !trimmed.contains("signer_account_id") {
                return false;
            }
            // Skip if it's only inside a string literal (rough check)
            let before_quote = trimmed.split('"').next().unwrap_or("");
            before_quote.contains("signer_account_id")
        });

        if !in_code {
            return;
        }

        // Check if signer is used in access control context
        let used_in_access_control = body_src.contains("assert")
            || body_src.contains("require")
            || body_src.contains("== ")
            || body_src.contains("!= ")
            || body_src.contains("owner")
            || body_src.contains("admin");

        if used_in_access_control {
            let line = span_to_line(&func.sig.ident.span());
            // Find the actual line with signer_account_id for better reporting
            let signer_line = self.ctx.source
                .lines()
                .enumerate()
                .find(|(_, l)| {
                    let t = l.trim();
                    t.contains("signer_account_id") && !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("*")
                })
                .map(|(i, _)| i + 1)
                .unwrap_or(line);

            self.findings.push(Finding {
                detector_id: "NEAR-002".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "Function '{}' uses signer_account_id() for access control instead of predecessor_account_id()",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line: signer_line,
                column: 1,
                snippet: snippet_at_line(&self.ctx.source, signer_line),
                recommendation: "Use env::predecessor_account_id() for access control. signer_account_id() returns the transaction originator which can differ from the direct caller in cross-contract calls".to_string(),
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
        );
        SignerVsPredecessorDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_signer_in_access_control() {
        let source = r#"
            fn admin_action(&mut self) {
                assert_eq!(env::signer_account_id(), self.owner, "Not owner");
                self.value = 42;
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect signer_account_id misuse");
    }

    #[test]
    fn test_no_finding_with_predecessor() {
        let source = r#"
            fn admin_action(&mut self) {
                assert_eq!(env::predecessor_account_id(), self.owner, "Not owner");
                self.value = 42;
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag predecessor_account_id");
    }
}
