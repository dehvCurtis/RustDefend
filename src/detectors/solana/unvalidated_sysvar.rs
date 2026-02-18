use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnvalidatedSysvarDetector;

impl Detector for UnvalidatedSysvarDetector {
    fn id(&self) -> &'static str {
        "SOL-021"
    }
    fn name(&self) -> &'static str {
        "unvalidated-sysvar"
    }
    fn description(&self) -> &'static str {
        "Detects sysvar parameters typed as AccountInfo without proper validation"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
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
        let mut visitor = SysvarVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const SYSVAR_NAMES: &[&str] = &[
    "clock",
    "rent",
    "epoch_schedule",
    "slot_hashes",
    "slot_history",
    "stake_history",
    "recent_blockhashes",
    "instructions",
];

struct SysvarVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SysvarVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        if fn_name.contains("test") || has_attribute(&func.attrs, "test") {
            return;
        }

        let fn_src = func.to_token_stream().to_string();

        // Skip if using Anchor's Sysvar<'info, T> type
        if fn_src.contains("Sysvar <") || fn_src.contains("Sysvar<") {
            return;
        }

        // Check if any parameter is a sysvar name typed as AccountInfo
        for param in &func.sig.inputs {
            let param_str = param.to_token_stream().to_string();

            // Check if param is typed as AccountInfo
            if !param_str.contains("AccountInfo") {
                continue;
            }

            // Check if param name matches a sysvar name
            let param_lower = param_str.to_lowercase();
            let is_sysvar_param = SYSVAR_NAMES.iter().any(|name| param_lower.contains(name));

            if !is_sysvar_param {
                continue;
            }

            let body_src = fn_body_source(func);

            // Check for proper sysvar validation
            let has_validation = body_src.contains("from_account_info")
                || body_src.contains("Sysvar :: get")
                || body_src.contains("Sysvar::get")
                || body_src.contains("sysvar::")
                || body_src.contains("Clock :: get")
                || body_src.contains("Clock::get")
                || body_src.contains("Rent :: get")
                || body_src.contains("Rent::get")
                || body_src.contains("EpochSchedule :: get")
                || body_src.contains("EpochSchedule::get");

            if !has_validation {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "SOL-021".to_string(),
                    name: "unvalidated-sysvar".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    message: format!(
                        "Function '{}' accepts sysvar as AccountInfo without from_account_info() or Sysvar::get() validation",
                        func.sig.ident
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Use Sysvar::get() or from_account_info() to validate sysvar accounts, or use Anchor's Sysvar<'info, T> type".to_string(),
                    chain: Chain::Solana,
                });
                break; // One finding per function
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
            Chain::Solana,
            std::collections::HashMap::new(),
        );
        UnvalidatedSysvarDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unvalidated_clock_sysvar() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn process(accounts: &[AccountInfo], clock_info: &AccountInfo) {
                let data = clock_info.try_borrow_data().unwrap();
                let timestamp = u64::from_le_bytes(data[32..40].try_into().unwrap());
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect unvalidated clock sysvar"
        );
    }

    #[test]
    fn test_detects_unvalidated_rent_sysvar() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn process(rent_account: &AccountInfo) {
                let data = rent_account.try_borrow_data().unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect unvalidated rent sysvar"
        );
    }

    #[test]
    fn test_no_finding_with_from_account_info() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn process(clock_info: &AccountInfo) {
                let clock = Clock::from_account_info(clock_info)?;
                let timestamp = clock.unix_timestamp;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with from_account_info validation"
        );
    }

    #[test]
    fn test_no_finding_with_sysvar_get() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn process(clock_info: &AccountInfo) {
                let clock = Clock::get()?;
                let timestamp = clock.unix_timestamp;
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with Sysvar::get()");
    }

    #[test]
    fn test_skips_anchor_sysvar_type() {
        let source = r#"
            use anchor_lang::prelude::*;
            fn process(clock: Sysvar<'info, Clock>) {
                let timestamp = clock.unix_timestamp;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should skip Anchor Sysvar<'info, T> type"
        );
    }

    #[test]
    fn test_no_finding_non_sysvar_account() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn process(user_account: &AccountInfo) {
                let data = user_account.try_borrow_data().unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag non-sysvar AccountInfo params"
        );
    }
}
