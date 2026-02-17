use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct RemainingAccountsDetector;

impl Detector for RemainingAccountsDetector {
    fn id(&self) -> &'static str {
        "SOL-013"
    }
    fn name(&self) -> &'static str {
        "unsafe-remaining-accounts"
    }
    fn description(&self) -> &'static str {
        "Detects ctx.remaining_accounts usage without owner/type/key validation"
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
        let mut visitor = RemainingAccountsVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const SAFE_PATTERNS: &[&str] = &[
    "owner",
    "try_deserialize",
    "Account :: try_from",
    "AccountDeserialize",
    "discriminator",
    "DISCRIMINATOR",
    "key () ==",
    "key() ==",
    "require_keys_eq",
    "require !",
    "require_eq",
];

const CPI_PASSTHROUGH_PATTERNS: &[&str] = &["invoke", "invoke_signed", "CpiContext"];

struct RemainingAccountsVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for RemainingAccountsVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let body_src = fn_body_source(func);

        if !body_src.contains("remaining_accounts") {
            return;
        }

        // Check for safe validation patterns
        let has_validation = SAFE_PATTERNS.iter().any(|p| body_src.contains(p));
        if has_validation {
            return;
        }

        // Check for CPI passthrough (target program validates)
        let is_cpi_passthrough = CPI_PASSTHROUGH_PATTERNS
            .iter()
            .any(|p| body_src.contains(p));
        // Only suppress if remaining_accounts is ONLY used for CPI passthrough
        // Heuristic: if remaining_accounts appears but no other usage beyond CPI context
        if is_cpi_passthrough {
            // Check if remaining_accounts is only used in CPI context
            // Simple heuristic: count occurrences of remaining_accounts
            let ra_count = body_src.matches("remaining_accounts").count();
            let cpi_count = CPI_PASSTHROUGH_PATTERNS
                .iter()
                .map(|p| body_src.matches(p).count())
                .sum::<usize>();
            if ra_count <= cpi_count {
                return;
            }
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "SOL-013".to_string(),
            name: "unsafe-remaining-accounts".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' uses ctx.remaining_accounts without owner/type/key validation",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Validate remaining_accounts by checking owner, deserializing with try_from/try_deserialize, or verifying keys with require_keys_eq!".to_string(),
            chain: Chain::Solana,
        });
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
        RemainingAccountsDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_remaining_accounts_without_validation() {
        let source = r#"
            fn process_swap(ctx: Context<Swap>) {
                for account in ctx.remaining_accounts.iter() {
                    let data = account.try_borrow_data()?;
                    process_data(&data);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect remaining_accounts without validation"
        );
        assert_eq!(findings[0].detector_id, "SOL-013");
    }

    #[test]
    fn test_no_finding_with_owner_check() {
        let source = r#"
            fn process_swap(ctx: Context<Swap>) {
                for account in ctx.remaining_accounts.iter() {
                    if account.owner != &spl_token::ID {
                        return Err(ErrorCode::InvalidOwner.into());
                    }
                    let data = account.try_borrow_data()?;
                    process_data(&data);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when owner check is present"
        );
    }

    #[test]
    fn test_no_finding_with_cpi_passthrough() {
        let source = r#"
            fn forward_accounts(ctx: Context<Forward>) {
                let cpi_ctx = CpiContext::new(ctx.accounts.program.to_account_info(), Transfer {})
                    .with_remaining_accounts(ctx.remaining_accounts.to_vec());
                invoke(cpi_ctx)?;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag CPI passthrough of remaining_accounts"
        );
    }
}
