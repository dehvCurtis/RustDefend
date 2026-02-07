use syn::visit::Visit;
use syn::ItemFn;
use quote::ToTokens;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct ArbitraryCpiDetector;

impl Detector for ArbitraryCpiDetector {
    fn id(&self) -> &'static str { "SOL-006" }
    fn name(&self) -> &'static str { "arbitrary-cpi" }
    fn description(&self) -> &'static str {
        "Detects CPI calls where the program target comes from untrusted input"
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn chain(&self) -> Chain { Chain::Solana }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = CpiVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct CpiVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for CpiVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_src = func.to_token_stream().to_string();

        // Skip if using Anchor's Program<'info, T> type (auto-validates)
        if fn_src.contains("Program <") || fn_src.contains("Program<") {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for CPI invocation patterns
        let has_cpi = body_src.contains("invoke (")
            || body_src.contains("invoke(")
            || body_src.contains("invoke_signed")
            || body_src.contains("CpiContext :: new")
            || body_src.contains("CpiContext::new");

        if !has_cpi {
            return;
        }

        let fn_name = func.sig.ident.to_string();

        // Skip helper/wrapper functions that pass through CPI
        // These are utility functions like spl_token_transfer, create_account, etc.
        // The actual program ID is typically hardcoded inside
        if fn_name.starts_with("spl_")
            || fn_name.starts_with("create_")
            || fn_name.starts_with("close_")
            || fn_name.starts_with("initialize_")
            || fn_name.starts_with("transfer_")
            || fn_name.starts_with("mint_")
            || fn_name.starts_with("burn_")
            || fn_name.starts_with("approve_")
            || fn_name.starts_with("revoke_")
            || fn_name.starts_with("freeze_")
            || fn_name.starts_with("thaw_")
            || fn_name.starts_with("sync_")
            || fn_name.contains("_invoke")
            || fn_name.contains("_cpi")
        {
            return;
        }

        // Check if the program ID is hardcoded or validated
        let has_program_check = body_src.contains("program_id ==")
            || body_src.contains("== program_id")
            || body_src.contains("key () ==")
            || body_src.contains("key() ==")
            || body_src.contains("system_program ::")
            || body_src.contains("system_program")
            || body_src.contains("token :: ID")
            || body_src.contains("token :: id")
            || body_src.contains("spl_token :: id")
            || body_src.contains("spl_token :: ID")
            || body_src.contains("token_program")
            || body_src.contains("Program <")
            // Common hardcoded program references
            || body_src.contains("system_instruction")
            || body_src.contains("spl_token")
            || body_src.contains("spl_associated")
            || body_src.contains("rent ::")
            || body_src.contains("Rent ::");

        if !has_program_check {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "SOL-006".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' performs CPI without verifying the target program",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Validate the program account key against an expected program ID, or use Anchor's `Program<'info, T>` constraint".to_string(),
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
        ArbitraryCpiDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_arbitrary_cpi() {
        let source = r#"
            fn do_transfer(program: &AccountInfo, from: &AccountInfo, to: &AccountInfo) {
                invoke(
                    &transfer_ix,
                    &[from.clone(), to.clone(), program.clone()],
                )?;
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect arbitrary CPI target");
    }

    #[test]
    fn test_no_finding_with_program_check() {
        let source = r#"
            fn do_transfer(program: &AccountInfo, from: &AccountInfo, to: &AccountInfo) {
                if program.key() == &spl_token::id() {
                    invoke(
                        &transfer_ix,
                        &[from.clone(), to.clone(), program.clone()],
                    )?;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with program ID check");
    }
}
