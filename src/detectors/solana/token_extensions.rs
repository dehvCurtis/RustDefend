use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct TokenExtensionsDetector;

impl Detector for TokenExtensionsDetector {
    fn id(&self) -> &'static str {
        "SOL-012"
    }
    fn name(&self) -> &'static str {
        "token-2022-extension-safety"
    }
    fn description(&self) -> &'static str {
        "Detects programs accepting Token-2022 tokens without checking for dangerous extensions"
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
        // Skip if the file implements a transfer hook itself
        if ctx.source.contains("TransferHookExecute") {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = TokenExtVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const TRIGGER_PATTERNS: &[&str] = &[
    "spl_token_2022",
    "Token2022",
    "InterfaceAccount",
    "token_interface",
    "TokenInterface",
    "transfer_checked",
];

const SAFE_PATTERNS: &[&str] = &[
    "get_extension_types",
    "PermanentDelegate",
    "TransferHook",
    "MintCloseAuthority",
    "ExtensionType",
    "ALLOWED_EXTENSION",
    "assert_mint_extensions",
    "valid_mint",
    "allowed_mint",
    "mint_whitelist",
    "mint_allowlist",
];

struct TokenExtVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for TokenExtVisitor<'a> {
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
        let body_src = fn_body_source(func);

        // Check if token_program is constrained to spl_token v1 only
        if fn_src.contains("spl_token :: id ()") || fn_src.contains("spl_token :: ID") {
            return;
        }

        // Check for trigger patterns
        let has_trigger = TRIGGER_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        if !has_trigger {
            return;
        }

        // Check for safe patterns
        let has_safe = SAFE_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        if has_safe {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "SOL-012".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' accepts Token-2022 tokens without checking for dangerous extensions (PermanentDelegate, TransferHook, MintCloseAuthority)",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Check mint extensions via get_extension_types() and reject mints with PermanentDelegate, TransferHook, or MintCloseAuthority extensions".to_string(),
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
        );
        TokenExtensionsDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_token2022_without_extension_check() {
        let source = r#"
            fn process_transfer(mint: &InterfaceAccount<Mint>, from: &InterfaceAccount<TokenAccount>) {
                let cpi_ctx = CpiContext::new(token_program.to_account_info(), Transfer {
                    from: from.to_account_info(),
                    to: to.to_account_info(),
                    authority: authority.to_account_info(),
                });
                transfer_checked(cpi_ctx, amount, mint.decimals)?;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect Token-2022 without extension check"
        );
        assert_eq!(findings[0].detector_id, "SOL-012");
    }

    #[test]
    fn test_no_finding_with_extension_check() {
        let source = r#"
            fn process_transfer(mint: &InterfaceAccount<Mint>) {
                let extensions = get_extension_types(&mint.to_account_info().data.borrow())?;
                if extensions.contains(&ExtensionType::PermanentDelegate) {
                    return Err(ErrorCode::UnsupportedExtension.into());
                }
                transfer_checked(cpi_ctx, amount, mint.decimals)?;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when extension check is present"
        );
    }

    #[test]
    fn test_no_finding_with_spl_token_v1_only() {
        let source = r#"
            fn process_transfer(token_program: AccountInfo) {
                // token_program constrained to spl_token :: ID
                assert_eq!(token_program.key, &spl_token :: ID);
                transfer_checked(cpi_ctx, amount, decimals);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when constrained to spl_token v1"
        );
    }
}
