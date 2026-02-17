use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct InitIfNeededDetector;

impl Detector for InitIfNeededDetector {
    fn id(&self) -> &'static str {
        "SOL-014"
    }
    fn name(&self) -> &'static str {
        "init-if-needed-reinitialization"
    }
    fn description(&self) -> &'static str {
        "Detects Anchor init_if_needed constraint without guard checks against reinitialization"
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
        // Skip test files
        let path_str = ctx.file_path.to_string_lossy();
        if path_str.contains("/tests/") || path_str.ends_with("_test.rs") {
            return Vec::new();
        }

        // Require Anchor-specific source markers — init_if_needed is an Anchor feature
        if !ctx.source.contains("anchor_lang")
            && !ctx.source.contains("Anchor")
            && !ctx.source.contains("#[account(")
            && !ctx.source.contains("#[derive(Accounts)]")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = InitIfNeededVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const SAFE_PATTERNS: &[&str] = &[
    "is_initialized",
    "initialized",
    "AlreadyInitialized",
    "AccountAlreadyInitialized",
    "already_initialized",
];

const SAFE_ACCOUNT_TYPES: &[&str] = &["TokenAccount", "AssociatedTokenAccount", "Mint"];

struct InitIfNeededVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for InitIfNeededVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let fn_src = func.to_token_stream().to_string();

        if !fn_src.contains("init_if_needed") {
            return;
        }

        // Check if the init_if_needed is on a token account type (safe)
        let has_safe_type = SAFE_ACCOUNT_TYPES.iter().any(|t| {
            // Look for init_if_needed near the safe account type in the attribute
            let src = &fn_src;
            if let Some(pos) = src.find("init_if_needed") {
                // Check surrounding context (within ~200 chars)
                let start = pos.saturating_sub(100);
                let end = (pos + 200).min(src.len());
                let context = &src[start..end];
                context.contains(t)
            } else {
                false
            }
        });

        if has_safe_type {
            return;
        }

        // Check for safe guard patterns in function body and surrounding source
        let body_src = fn_body_source(func);
        let has_guard = SAFE_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        // Also check for constraint = in the same attribute block as init_if_needed
        let has_constraint = {
            if let Some(pos) = fn_src.find("init_if_needed") {
                let start = pos.saturating_sub(200);
                let end = (pos + 300).min(fn_src.len());
                let context = &fn_src[start..end];
                context.contains("constraint =")
            } else {
                false
            }
        };

        if has_guard || has_constraint {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "SOL-014".to_string(),
            name: "init-if-needed-reinitialization".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' uses init_if_needed without reinitialization guard",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Add an is_initialized check or constraint to prevent reinitialization attacks when using init_if_needed".to_string(),
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
        InitIfNeededDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_init_if_needed_without_guard() {
        let source = r#"
            fn initialize_user(ctx: Context<InitUser>) {
                // #[account(init_if_needed, payer = user, space = 8 + UserData::LEN)]
                let user_data = &mut ctx.accounts.user_data;
                user_data.init_if_needed;
                user_data.authority = ctx.accounts.user.key();
                user_data.balance = 0;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect init_if_needed without guard"
        );
        assert_eq!(findings[0].detector_id, "SOL-014");
    }

    #[test]
    fn test_no_finding_with_is_initialized_check() {
        let source = r#"
            fn initialize_user(ctx: Context<InitUser>) {
                // #[account(init_if_needed, payer = user, space = 8 + UserData::LEN)]
                let user_data = &mut ctx.accounts.user_data;
                user_data.init_if_needed;
                if user_data.is_initialized {
                    return Err(ErrorCode::AlreadyInitialized.into());
                }
                user_data.authority = ctx.accounts.user.key();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when is_initialized check present"
        );
    }

    #[test]
    fn test_no_finding_with_token_account() {
        let source = r#"
            fn initialize_ata(ctx: Context<InitAta>) {
                // TokenAccount is safe - token program manages state
                let ata: Account<TokenAccount> = ctx.accounts.init_if_needed;
                let balance = ata.amount;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag TokenAccount with init_if_needed"
        );
    }
}
