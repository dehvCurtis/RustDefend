use syn::visit::Visit;
use syn::{Expr, Pat, Stmt};
use quote::ToTokens;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UncheckedReturnDetector;

impl Detector for UncheckedReturnDetector {
    fn id(&self) -> &'static str { "SOL-008" }
    fn name(&self) -> &'static str { "unchecked-cpi-return" }
    fn description(&self) -> &'static str {
        "Detects CPI calls whose return value is discarded"
    }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn chain(&self) -> Chain { Chain::Solana }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ReturnVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ReturnVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ReturnVisitor<'a> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        // Look for `let _ = invoke(...)` pattern
        if let Stmt::Local(local) = stmt {
            if let Pat::Wild(_) = &local.pat {
                if let Some(init) = &local.init {
                    let expr_str = init.expr.to_token_stream().to_string();
                    if expr_str.contains("invoke")
                        || expr_str.contains("invoke_signed")
                    {
                        let line = span_to_line(&local.pat.span());
                        self.findings.push(Finding {
                            detector_id: "SOL-008".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            message: "CPI call result is discarded with `let _ = ...`".to_string(),
                            file: self.ctx.file_path.clone(),
                            line,
                            column: span_to_column(&local.pat.span()),
                            snippet: snippet_at_line(&self.ctx.source, line),
                            recommendation: "Propagate the error using `?` operator: `invoke(...)?.`".to_string(),
                            chain: Chain::Solana,
                        });
                    }
                }
            }
        }

        // Also check for bare invoke() without ? or error handling (expression statement)
        if let Stmt::Expr(expr, Some(_semi)) = stmt {
            let expr_str = expr.to_token_stream().to_string();
            if (expr_str.contains("invoke (") || expr_str.contains("invoke(")
                || expr_str.contains("invoke_signed"))
                && !expr_str.contains('?')
                && !expr_str.contains("unwrap")
                && !expr_str.contains("expect")
                && !expr_str.contains("match")
            {
                let line = span_to_line(&expr.span());
                self.findings.push(Finding {
                    detector_id: "SOL-008".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: "CPI call result is ignored".to_string(),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&expr.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Handle the CPI result with `?` operator or explicit error handling".to_string(),
                    chain: Chain::Solana,
                });
            }
        }

        syn::visit::visit_stmt(self, stmt);
    }
}

use proc_macro2::Span;

trait SpanAccess {
    fn span(&self) -> Span;
}

impl SpanAccess for Pat {
    fn span(&self) -> Span {
        match self {
            Pat::Wild(w) => w.underscore_token.span,
            _ => Span::call_site(),
        }
    }
}

impl SpanAccess for Expr {
    fn span(&self) -> Span {
        // Use call_site as fallback since we can't easily get span from all expr types
        Span::call_site()
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
        UncheckedReturnDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_discarded_result() {
        let source = r#"
            fn do_cpi() {
                let _ = invoke(&instruction, &accounts);
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect discarded CPI result");
    }

    #[test]
    fn test_no_finding_with_question_mark() {
        let source = r#"
            fn do_cpi() -> Result<(), ProgramError> {
                invoke(&instruction, &accounts)?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag when ? is used");
    }
}
