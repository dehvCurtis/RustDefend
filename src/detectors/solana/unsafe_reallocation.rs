use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnsafeReallocationDetector;

impl Detector for UnsafeReallocationDetector {
    fn id(&self) -> &'static str {
        "SOL-018"
    }
    fn name(&self) -> &'static str {
        "unsafe-account-reallocation"
    }
    fn description(&self) -> &'static str {
        "Detects .realloc() calls without signer and rent/lamport checks"
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
        let mut visitor = ReallocVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ReallocVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ReallocVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        if fn_name.contains("test") || has_attribute(&func.attrs, "test") {
            return;
        }

        let fn_src = func.to_token_stream().to_string();

        // Skip Anchor #[account(realloc = ...)] patterns
        // Tokenized form: # [account (...realloc =...)]
        if fn_src.contains("realloc =") || fn_src.contains("realloc=") {
            if fn_src.contains("# [account")
                || fn_src.contains("#[account")
                || fn_src.contains("account (")
            {
                return;
            }
        }

        let body_src = fn_body_source(func);

        // Check for .realloc() call
        if !body_src.contains(".realloc(") && !body_src.contains(". realloc (") {
            return;
        }

        let has_signer_check = body_src.contains("is_signer")
            || body_src.contains("has_signer")
            || body_src.contains("Signer");

        let has_rent_check = body_src.contains("rent")
            || body_src.contains("Rent")
            || body_src.contains("lamport")
            || body_src.contains("minimum_balance");

        if !has_signer_check || !has_rent_check {
            let line = span_to_line(&func.sig.ident.span());
            let mut missing = Vec::new();
            if !has_signer_check {
                missing.push("signer check");
            }
            if !has_rent_check {
                missing.push("rent/lamport check");
            }
            self.findings.push(Finding {
                detector_id: "SOL-018".to_string(),
                name: "unsafe-account-reallocation".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' calls .realloc() without {}",
                    func.sig.ident,
                    missing.join(" and ")
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Verify the caller is a signer and ensure rent exemption is maintained after reallocation, or use Anchor's #[account(realloc = ...)]".to_string(),
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
        UnsafeReallocationDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_realloc_without_checks() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn resize_account(account: &AccountInfo) {
                account.realloc(new_size, false).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect realloc without signer and rent checks"
        );
    }

    #[test]
    fn test_no_finding_with_both_checks() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn resize_account(account: &AccountInfo, authority: &AccountInfo) {
                if !authority.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                let rent = Rent::get()?;
                let min_balance = rent.minimum_balance(new_size);
                account.realloc(new_size, false).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with signer + rent checks"
        );
    }

    #[test]
    fn test_detects_realloc_missing_signer_only() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn resize_account(account: &AccountInfo) {
                let rent = Rent::get()?;
                account.realloc(new_size, false).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect realloc missing signer check"
        );
        assert!(findings[0].message.contains("signer check"));
    }

    #[test]
    fn test_skips_anchor_realloc_attribute() {
        let source = r#"
            use anchor_lang::prelude::*;
            #[account(realloc = space)]
            fn process(ctx: Context<Resize>) {
                ctx.accounts.data.realloc(new_size, false).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should skip Anchor realloc attribute patterns"
        );
    }
}
