use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;
use crate::utils::call_graph::{self, CheckKind};

pub struct MissingOwnerDetector;

impl Detector for MissingOwnerDetector {
    fn id(&self) -> &'static str {
        "SOL-002"
    }
    fn name(&self) -> &'static str {
        "missing-owner-check"
    }
    fn description(&self) -> &'static str {
        "Detects deserialization of account data without verifying account owner"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Require Solana-specific source markers to avoid cross-chain FPs
        if !ctx.source.contains("solana_program")
            && !ctx.source.contains("anchor_lang")
            && !ctx.source.contains("AccountInfo")
            && !ctx.source.contains("ProgramResult")
            && !ctx.source.contains("solana_sdk")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = OwnerVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct OwnerVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for OwnerVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_src = func.to_token_stream().to_string();

        // Skip Anchor patterns (Account<'info, T> handles this automatically)
        if fn_src.contains("Account <") || fn_src.contains("Account<") {
            if !fn_src.contains("AccountInfo") {
                return;
            }
        }

        let body_src = fn_body_source(func);

        // Look for deserialization patterns
        let deser_patterns = [
            "deserialize",
            "try_from_slice",
            "unpack",
            "try_deserialize",
            "try_borrow_data",
        ];

        let has_deserialization = deser_patterns.iter().any(|p| body_src.contains(p));
        if !has_deserialization {
            return;
        }

        // Check for owner verification
        let has_owner_check = body_src.contains("owner")
            && (body_src.contains("program_id") || body_src.contains("key ()"));

        // Check if any caller in the same file already checks owner (call graph analysis)
        if !has_owner_check {
            let fn_name = func.sig.ident.to_string();
            if call_graph::caller_has_check(&self.ctx.call_graph, &fn_name, CheckKind::OwnerCheck) {
                return;
            }
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "SOL-002".to_string(),
                name: "missing-owner-check".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                message: format!(
                    "Function '{}' deserializes account data without verifying account owner",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add `if account.owner != program_id { return Err(...) }` before deserialization, or use Anchor's `Account<'info, T>`".to_string(),
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
        let graph = crate::utils::call_graph::build_call_graph(&ast);
        let ctx = ScanContext::new(
            std::path::PathBuf::from("test.rs"),
            source.to_string(),
            ast,
            Chain::Solana,
            graph,
        );
        MissingOwnerDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_owner_check() {
        let source = r#"
            fn process(account: &AccountInfo) {
                let data = MyData::deserialize(&mut &account.data.borrow()[..]).unwrap();
                data.amount += 100;
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing owner check");
    }

    #[test]
    fn test_no_finding_caller_checks_owner() {
        let source = r#"
            fn process(account: &AccountInfo, program_id: &Pubkey) {
                if account.owner != program_id {
                    return Err(ProgramError::IncorrectProgramId);
                }
                helper(account);
            }

            fn helper(account: &AccountInfo) {
                let data = MyData::deserialize(&mut &account.data.borrow()[..]).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when caller checks owner (call graph analysis)"
        );
    }

    #[test]
    fn test_no_finding_with_owner_check() {
        let source = r#"
            fn process(account: &AccountInfo, program_id: &Pubkey) {
                if account.owner != program_id {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let data = MyData::deserialize(&mut &account.data.borrow()[..]).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with owner check");
    }
}
