use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct PdaIssuesDetector;

impl Detector for PdaIssuesDetector {
    fn id(&self) -> &'static str {
        "SOL-007"
    }
    fn name(&self) -> &'static str {
        "pda-bump-misuse"
    }
    fn description(&self) -> &'static str {
        "Detects create_program_address with user-provided bump seeds"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = PdaVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct PdaVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for PdaVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Check for create_program_address usage (bump from args)
        if body_src.contains("create_program_address") {
            // If they also use find_program_address, likely safe
            if !body_src.contains("find_program_address") {
                let line = span_to_line(&func.sig.ident.span());

                // Check if bump comes from function parameters
                let fn_src = func.to_token_stream().to_string();
                let has_bump_param = fn_src.contains("bump")
                    || (body_src.contains("create_program_address")
                        && !body_src.contains("find_program_address"));

                if has_bump_param {
                    self.findings.push(Finding {
                        detector_id: "SOL-007".to_string(),
                        name: "pda-bump-misuse".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        message: format!(
                            "Function '{}' uses create_program_address without find_program_address (user-provided bump)",
                            func.sig.ident
                        ),
                        file: self.ctx.file_path.clone(),
                        line,
                        column: span_to_column(&func.sig.ident.span()),
                        snippet: snippet_at_line(&self.ctx.source, line),
                        recommendation: "Use find_program_address() which returns the canonical bump, or verify the provided bump against find_program_address result".to_string(),
                        chain: Chain::Solana,
                    });
                }
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
        );
        PdaIssuesDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_user_bump() {
        let source = r#"
            fn verify_pda(bump: u8, seeds: &[u8], program_id: &Pubkey) {
                let pda = Pubkey::create_program_address(&[seeds, &[bump]], program_id).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect user-provided bump");
    }

    #[test]
    fn test_no_finding_with_find() {
        let source = r#"
            fn verify_pda(seeds: &[u8], program_id: &Pubkey) {
                let (pda, bump) = Pubkey::find_program_address(&[seeds], program_id);
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag find_program_address");
    }
}
