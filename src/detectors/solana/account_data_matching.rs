use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct AccountDataMatchingDetector;

impl Detector for AccountDataMatchingDetector {
    fn id(&self) -> &'static str {
        "SOL-017"
    }
    fn name(&self) -> &'static str {
        "account-data-matching"
    }
    fn description(&self) -> &'static str {
        "Detects account data deserialization without field validation"
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
        if !ctx.source.contains("solana_program")
            && !ctx.source.contains("anchor_lang")
            && !ctx.source.contains("AccountInfo")
            && !ctx.source.contains("ProgramResult")
            && !ctx.source.contains("solana_sdk")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = DataMatchingVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct DataMatchingVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for DataMatchingVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip validation/verification/parsing utility functions and tests
        if fn_name.contains("validate")
            || fn_name.contains("verify")
            || fn_name.contains("check")
            || fn_name.contains("parse")
            || fn_name.contains("unpack")
            || fn_name.contains("test")
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

        // Check for data borrowing/deserialization
        let has_data_access = body_src.contains("try_borrow_data")
            || body_src.contains("data . borrow")
            || body_src.contains("data.borrow")
            || body_src.contains("try_from_slice")
            || body_src.contains("deserialize");

        if !has_data_access {
            return;
        }

        // Check for field validation after deserialization
        // Note: tokenized source uses spaces around operators and macros
        // e.g., "assert_eq !" for "assert_eq!", "= =" for "=="
        let has_validation = body_src.contains("assert_eq")
            || body_src.contains("assert_ne")
            || body_src.contains("= =")
            || body_src.contains("! =")
            || body_src.contains("==")
            || body_src.contains("!=")
            || body_src.contains("require")
            || body_src.contains("discriminator")
            || body_src.contains("DISCRIMINATOR")
            || body_src.contains("is_initialized")
            || body_src.contains("IsInitialized");

        if !has_validation {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "SOL-017".to_string(),
                name: "account-data-matching".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' borrows/deserializes account data without field validation",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Validate deserialized account fields (e.g., assert_eq!, require!, discriminator check) before using the data, or use Anchor's Account<'info, T>".to_string(),
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
            std::collections::HashMap::new(),
        );
        AccountDataMatchingDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_field_validation() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn load_data(account: &AccountInfo) {
                let data = account.try_borrow_data().unwrap();
                let state = MyState::try_from_slice(&data).unwrap();
                process(state);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect missing field validation"
        );
    }

    #[test]
    fn test_no_finding_with_assert_eq() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn load_data(account: &AccountInfo) {
                let data = account.try_borrow_data().unwrap();
                let state = MyState::try_from_slice(&data).unwrap();
                assert_eq!(state.owner, expected_owner);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with assert_eq! validation"
        );
    }

    #[test]
    fn test_no_finding_with_require() {
        let source = r#"
            use anchor_lang::prelude::*;
            fn load_data(account: &AccountInfo) {
                let data = account.try_borrow_data().unwrap();
                let state = MyState::try_from_slice(&data).unwrap();
                require!(state.is_initialized, MyError::NotInitialized);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with require! validation"
        );
    }

    #[test]
    fn test_skips_anchor_context() {
        let source = r#"
            use anchor_lang::prelude::*;
            fn process(ctx: Context<MyAccounts>) {
                let account: Account<'_, MyState> = Account::try_from(&ctx.accounts.my_account).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should skip Anchor Account<> + Context patterns"
        );
    }

    #[test]
    fn test_skips_validate_functions() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn validate_account(account: &AccountInfo) {
                let data = account.try_borrow_data().unwrap();
                let state = MyState::try_from_slice(&data).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should skip validation functions");
    }
}
