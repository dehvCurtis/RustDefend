use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct AccountConfusionDetector;

impl Detector for AccountConfusionDetector {
    fn id(&self) -> &'static str {
        "SOL-004"
    }
    fn name(&self) -> &'static str {
        "account-confusion"
    }
    fn description(&self) -> &'static str {
        "Detects manual account deserialization without discriminator check"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ConfusionVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ConfusionVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ConfusionVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test/pack/unpack/deserialization utility functions
        if fn_name.contains("test")
            || fn_name.starts_with("pack")
            || fn_name.starts_with("unpack")
            || fn_name.contains("_pack")
            || fn_name.contains("_unpack")
            || fn_name.contains("deserialize")
            || fn_name.contains("serialize")
            || fn_name.starts_with("gen_")
            || fn_name.starts_with("generate_")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let fn_src = func.to_token_stream().to_string();

        // Skip Anchor Account<'info, T> patterns
        if fn_src.contains("Account <") || fn_src.contains("Account<") {
            if fn_src.contains("Context") {
                return;
            }
        }

        let body_src = fn_body_source(func);

        // Check for manual deserialization
        let has_deser = body_src.contains("try_from_slice")
            || body_src.contains("deserialize")
            || body_src.contains("unpack");

        if !has_deser {
            return;
        }

        // Check for discriminator check (first 8 bytes)
        let has_discriminator = body_src.contains("discriminator")
            || body_src.contains("[.. 8]")
            || body_src.contains("[..8]")
            || body_src.contains("DISCRIMINATOR")
            || body_src.contains("account_type")
            || body_src.contains("is_initialized")
            || body_src.contains("IsInitialized")
            || fn_src.contains("IsInitialized")
            || body_src.contains("assert_initialized");

        if !has_discriminator {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "SOL-004".to_string(),
                name: "account-confusion".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' deserializes account data without discriminator validation",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Check the first 8 bytes of account data as a discriminator before deserialization, or use Anchor's `Account<'info, T>`".to_string(),
                chain: Chain::Solana,
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
            Chain::Solana,
        );
        AccountConfusionDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_discriminator() {
        let source = r#"
            fn load_account(account: &AccountInfo) {
                let data = MyState::try_from_slice(&account.data.borrow()).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing discriminator");
    }

    #[test]
    fn test_no_finding_with_discriminator() {
        let source = r#"
            fn load_account(account: &AccountInfo) {
                let data = account.data.borrow();
                if data[..8] != MyState::DISCRIMINATOR {
                    return Err(ProgramError::InvalidAccountData);
                }
                let state = MyState::try_from_slice(&data[8..]).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with discriminator check"
        );
    }
}
