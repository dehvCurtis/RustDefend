use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct SelfCallbackDetector;

impl Detector for SelfCallbackDetector {
    fn id(&self) -> &'static str { "NEAR-007" }
    fn name(&self) -> &'static str { "self-callback-state" }
    fn description(&self) -> &'static str {
        "Detects pending state field writes before ext_self:: calls without guard checks"
    }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn chain(&self) -> Chain { Chain::Near }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = SelfCallbackVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct SelfCallbackVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SelfCallbackVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Must have ext_self call
        if !body_src.contains("ext_self") {
            return;
        }

        // Check for pending_ field writes
        let has_pending_write = body_src.contains("pending_")
            && body_src.contains("self .")
            && body_src.contains('=');

        if !has_pending_write {
            return;
        }

        // Check for guard (tokenized form has space: "assert !")
        let has_guard = body_src.contains("assert !")
            || body_src.contains("assert!")
            || body_src.contains("require !")
            || body_src.contains("require!")
            || body_src.contains("if self . pending")
            || body_src.contains("if self.pending");

        if !has_guard {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "NEAR-007".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' sets pending state before ext_self callback without guard",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add a guard check for pending state (e.g., assert!(!self.pending_withdrawal)) before setting it, and clear it in the callback".to_string(),
                chain: Chain::Near,
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
            Chain::Near,
        );
        SelfCallbackDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unguarded_pending() {
        let source = r#"
            fn initiate_withdrawal(&mut self, amount: u128) {
                self.pending_amount = amount;
                ext_self::on_withdrawal_complete(env::current_account_id(), 0, GAS);
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unguarded pending state");
    }

    #[test]
    fn test_no_finding_with_guard() {
        let source = r#"
            fn initiate_withdrawal(&mut self, amount: u128) {
                assert!(!self.pending_withdrawal, "Already pending");
                self.pending_amount = amount;
                ext_self::on_withdrawal_complete(env::current_account_id(), 0, GAS);
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with guard");
    }
}
