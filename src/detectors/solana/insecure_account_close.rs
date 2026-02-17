use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct InsecureAccountCloseDetector;

impl Detector for InsecureAccountCloseDetector {
    fn id(&self) -> &'static str {
        "SOL-005"
    }
    fn name(&self) -> &'static str {
        "insecure-account-close"
    }
    fn description(&self) -> &'static str {
        "Detects account closure that doesn't zero data and set discriminator"
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
        let mut visitor = CloseVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct CloseVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for CloseVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_src = func.to_token_stream().to_string();

        // Skip Anchor close = recipient pattern
        if fn_src.contains("close =") || fn_src.contains("close=") {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for lamport zeroing (account closure pattern)
        let has_lamport_zero = body_src.contains("lamports")
            && (body_src.contains("= 0") || body_src.contains("borrow_mut"));

        if !has_lamport_zero {
            return;
        }

        // Check if data is also zeroed
        let has_data_zero = body_src.contains("fill (0)")
            || body_src.contains("fill(0)")
            || body_src.contains("sol_memset")
            || body_src.contains("data . fill")
            || body_src.contains("CLOSED_ACCOUNT_DISCRIMINATOR");

        if !has_data_zero {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "SOL-005".to_string(),
                name: "insecure-account-close".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' closes account by zeroing lamports without clearing data/discriminator",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "After zeroing lamports, also zero account data and set the discriminator to CLOSED_ACCOUNT_DISCRIMINATOR, or use Anchor's #[account(close = recipient)]".to_string(),
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
        InsecureAccountCloseDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_insecure_close() {
        let source = r#"
            fn close_account(account: &AccountInfo, dest: &AccountInfo) {
                let dest_lamports = dest.lamports();
                **dest.lamports.borrow_mut() = dest_lamports + account.lamports();
                **account.lamports.borrow_mut() = 0;
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect insecure account close");
    }

    #[test]
    fn test_no_finding_with_data_zero() {
        let source = r#"
            fn close_account(account: &AccountInfo, dest: &AccountInfo) {
                **dest.lamports.borrow_mut() += account.lamports();
                **account.lamports.borrow_mut() = 0;
                account.data.borrow_mut().fill(0);
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag when data is zeroed");
    }
}
