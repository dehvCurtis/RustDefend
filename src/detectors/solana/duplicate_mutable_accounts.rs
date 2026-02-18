use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct DuplicateMutableAccountsDetector;

impl Detector for DuplicateMutableAccountsDetector {
    fn id(&self) -> &'static str {
        "SOL-019"
    }
    fn name(&self) -> &'static str {
        "duplicate-mutable-accounts"
    }
    fn description(&self) -> &'static str {
        "Detects functions with multiple mutable AccountInfo params without key uniqueness check"
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
        let mut visitor = DuplicateMutableVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct DuplicateMutableVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for DuplicateMutableVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        if fn_name.contains("test") || has_attribute(&func.attrs, "test") {
            return;
        }

        let fn_src = func.to_token_stream().to_string();

        // Skip Anchor Context<T> patterns — Anchor validates key uniqueness
        if fn_src.contains("Context <") || fn_src.contains("Context<") {
            return;
        }

        // Count AccountInfo parameters
        let account_info_count = func
            .sig
            .inputs
            .iter()
            .filter(|arg| {
                let arg_str = arg.to_token_stream().to_string();
                arg_str.contains("AccountInfo")
            })
            .count();

        if account_info_count < 2 {
            return;
        }

        let body_src = fn_body_source(func);

        // Check for mutable data access
        let has_mut_access =
            body_src.contains("try_borrow_mut_data") || body_src.contains("borrow_mut");

        if !has_mut_access {
            return;
        }

        // Check for key uniqueness assertion
        // Note: tokenized source uses spaces (e.g., "! =" for "!=")
        // and macros have space before ! (e.g., "assert_ne !")
        let has_key_check = body_src.contains("key !=")
            || body_src.contains("key ! =")
            || body_src.contains("key () !=")
            || body_src.contains("key () ! =")
            || body_src.contains("key() !=")
            || body_src.contains("!= key")
            || body_src.contains("! = key")
            || body_src.contains("require_keys_neq")
            || body_src.contains("assert_ne")
            || body_src.contains("require_keys_eq");

        if !has_key_check {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "SOL-019".to_string(),
                name: "duplicate-mutable-accounts".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' has {} AccountInfo params with mutable access but no key uniqueness assertion",
                    func.sig.ident, account_info_count
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Assert that account keys are not equal (e.g., require_keys_neq! or assert_ne!(a.key, b.key)) to prevent duplicate mutable account attacks, or use Anchor's Context<T>".to_string(),
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
        DuplicateMutableAccountsDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_duplicate_mutable_no_check() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn transfer(from: &AccountInfo, to: &AccountInfo) {
                let mut from_data = from.try_borrow_mut_data()?;
                let mut to_data = to.try_borrow_mut_data()?;
                from_data[0] -= 1;
                to_data[0] += 1;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect duplicate mutable accounts without key check"
        );
    }

    #[test]
    fn test_no_finding_with_key_check() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn transfer(from: &AccountInfo, to: &AccountInfo) {
                assert_ne!(from.key, to.key);
                let mut from_data = from.try_borrow_mut_data()?;
                let mut to_data = to.try_borrow_mut_data()?;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with key uniqueness assertion"
        );
    }

    #[test]
    fn test_no_finding_single_account() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn update(account: &AccountInfo) {
                let mut data = account.try_borrow_mut_data()?;
                data[0] = 1;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag single AccountInfo param"
        );
    }

    #[test]
    fn test_skips_anchor_context() {
        let source = r#"
            use anchor_lang::prelude::*;
            fn transfer(ctx: Context<Transfer>, from: &AccountInfo, to: &AccountInfo) {
                let mut from_data = from.try_borrow_mut_data()?;
                let mut to_data = to.try_borrow_mut_data()?;
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should skip Anchor Context patterns");
    }
}
