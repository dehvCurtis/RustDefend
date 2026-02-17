use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct PriorityFeeDetector;

impl Detector for PriorityFeeDetector {
    fn id(&self) -> &'static str {
        "SOL-016"
    }
    fn name(&self) -> &'static str {
        "missing-priority-fee"
    }
    fn description(&self) -> &'static str {
        "Detects set_compute_unit_limit without set_compute_unit_price (missing priority fee)"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn confidence(&self) -> Confidence {
        Confidence::Low
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Quick check: skip files that don't mention compute budget at all
        if !ctx.source.contains("set_compute_unit_limit")
            && !ctx.source.contains("ComputeBudgetInstruction")
        {
            return Vec::new();
        }

        // File-level check: if set_compute_unit_price or compute_unit_price
        // appears anywhere in the file, the developer is already handling priority fees
        if ctx.source.contains("set_compute_unit_price")
            || ctx.source.contains("compute_unit_price")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = PriorityFeeVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const TRIGGER_PATTERNS: &[&str] = &["set_compute_unit_limit", "ComputeBudgetInstruction"];

struct PriorityFeeVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for PriorityFeeVisitor<'a> {
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

        // Check for trigger patterns
        let has_trigger = TRIGGER_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        if !has_trigger {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "SOL-016".to_string(),
            name: "missing-priority-fee".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Low,
            message: format!(
                "Function '{}' sets compute unit limit without setting compute unit price (priority fee)",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Add ComputeBudgetInstruction::set_compute_unit_price() alongside compute unit limit to ensure transaction priority".to_string(),
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
        PriorityFeeDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_compute_limit_without_price() {
        let source = r#"
            fn build_transaction(payer: &Keypair) {
                let limit_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
                let instructions = vec![limit_ix, main_instruction];
                let tx = Transaction::new_signed_with_payer(
                    &instructions,
                    Some(&payer.pubkey()),
                    &[payer],
                    recent_blockhash,
                );
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect compute unit limit without price"
        );
        assert_eq!(findings[0].detector_id, "SOL-016");
    }

    #[test]
    fn test_no_finding_with_both_limit_and_price() {
        let source = r#"
            fn build_transaction(payer: &Keypair) {
                let limit_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
                let price_ix = ComputeBudgetInstruction::set_compute_unit_price(1_000);
                let instructions = vec![limit_ix, price_ix, main_instruction];
                let tx = Transaction::new_signed_with_payer(
                    &instructions,
                    Some(&payer.pubkey()),
                    &[payer],
                    recent_blockhash,
                );
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when both limit and price are set"
        );
    }
}
