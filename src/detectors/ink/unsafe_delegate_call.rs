use syn::visit::Visit;
use syn::ImplItemFn;
use quote::ToTokens;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnsafeDelegateCallDetector;

impl Detector for UnsafeDelegateCallDetector {
    fn id(&self) -> &'static str { "INK-009" }
    fn name(&self) -> &'static str { "ink-unsafe-delegate-call" }
    fn description(&self) -> &'static str {
        "Detects delegate_call with user-controlled code hash (arbitrary code execution)"
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn chain(&self) -> Chain { Chain::Ink }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = DelegateVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct DelegateVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for DelegateVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let body_src = method.block.to_token_stream().to_string();

        // Look for delegate call patterns
        if !body_src.contains("delegate") && !body_src.contains("DelegateCall") {
            return;
        }

        // Check if the delegate target comes from function parameters
        let sig_src = method.sig.to_token_stream().to_string();
        let has_hash_param = sig_src.contains("Hash")
            || sig_src.contains("code_hash")
            || sig_src.contains("target");

        // Check for hardcoded hash verification
        let has_verification = body_src.contains("assert_eq !")
            || body_src.contains("assert_eq!")
            || body_src.contains("KNOWN_HASH")
            || body_src.contains("ALLOWED_HASH")
            || body_src.contains("whitelist")
            || body_src.contains("allowed_hashes");

        if has_hash_param && !has_verification {
            let fn_name = method.sig.ident.to_string();
            let line = span_to_line(&method.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "INK-009".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                message: format!(
                    "Method '{}' performs delegate_call with user-controlled code hash",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&method.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Validate the code hash against a whitelist before delegate_call to prevent arbitrary code execution".to_string(),
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
        UnsafeDelegateCallDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unsafe_delegate() {
        let source = r#"
            impl MyContract {
                pub fn proxy_call(&mut self, target_hash: Hash, input: Vec<u8>) {
                    ink::env::call::build_call::<Environment>()
                        .delegate(target_hash)
                        .exec_input(input)
                        .fire();
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unsafe delegate call");
    }

    #[test]
    fn test_no_finding_with_verification() {
        let source = r#"
            impl MyContract {
                pub fn proxy_call(&mut self, target_hash: Hash, input: Vec<u8>) {
                    assert_eq!(target_hash, KNOWN_HASH);
                    ink::env::call::build_call::<Environment>()
                        .delegate(target_hash)
                        .fire();
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with hash verification");
    }
}
