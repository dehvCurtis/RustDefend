use quote::ToTokens;
use syn::visit::Visit;
use syn::{ItemFn, Stmt};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct CpiReentrancyDetector;

impl Detector for CpiReentrancyDetector {
    fn id(&self) -> &'static str {
        "SOL-009"
    }
    fn name(&self) -> &'static str {
        "cpi-reentrancy"
    }
    fn description(&self) -> &'static str {
        "Detects state mutations after CPI calls (CEI violation) - mitigated by Solana's account locking"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Low
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ReentrancyVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ReentrancyVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ReentrancyVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let stmts = &func.block.stmts;
        let mut seen_cpi = false;
        let mut cpi_line = 0usize;

        for stmt in stmts {
            let stmt_str = stmt.to_token_stream().to_string();

            // Check for CPI calls
            if stmt_str.contains("invoke (")
                || stmt_str.contains("invoke(")
                || stmt_str.contains("invoke_signed")
                || stmt_str.contains("CpiContext")
            {
                seen_cpi = true;
                cpi_line = get_stmt_line(stmt);
            }

            // If we've seen a CPI, check for state mutations after it
            if seen_cpi {
                let is_mutation = stmt_str.contains("serialize")
                    || stmt_str.contains("try_borrow_mut")
                    || stmt_str.contains("borrow_mut")
                    || (stmt_str.contains("data") && stmt_str.contains("= "));

                // Skip the CPI line itself
                let stmt_line = get_stmt_line(stmt);
                if is_mutation && stmt_line > cpi_line {
                    self.findings.push(Finding {
                        detector_id: "SOL-009".to_string(),
                        name: "cpi-reentrancy".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        message: format!(
                            "Function '{}' mutates state after CPI call (CEI violation)",
                            func.sig.ident
                        ),
                        file: self.ctx.file_path.clone(),
                        line: stmt_line,
                        column: 1,
                        snippet: snippet_at_line(&self.ctx.source, stmt_line),
                        recommendation: "Solana's account locking mitigates CPI reentrancy, but CEI violations should be avoided for defense-in-depth. Move state mutations before CPI calls".to_string(),
                        chain: Chain::Solana,
                    });
                }
            }
        }
    }
}

fn get_stmt_line(stmt: &Stmt) -> usize {
    match stmt {
        Stmt::Local(local) => span_to_line(&local.let_token.span),
        Stmt::Expr(expr, _) => {
            // Best effort line extraction
            let tokens = expr.to_token_stream();
            let span = tokens
                .into_iter()
                .next()
                .map(|t| t.span())
                .unwrap_or_else(proc_macro2::Span::call_site);
            span_to_line(&span)
        }
        Stmt::Item(_) => 0,
        Stmt::Macro(m) => span_to_line(&m.mac.path.span()),
    }
}

use proc_macro2::Span;

trait PathSpan {
    fn span(&self) -> Span;
}

impl PathSpan for syn::Path {
    fn span(&self) -> Span {
        self.segments
            .first()
            .map(|s| s.ident.span())
            .unwrap_or_else(Span::call_site)
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
        CpiReentrancyDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_state_after_cpi() {
        let source = r#"
            fn process(accounts: &[AccountInfo]) -> ProgramResult {
                invoke(&ix, &accounts)?;
                let mut data = account.try_borrow_mut_data()?;
                data[0] = 1;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect state mutation after CPI"
        );
    }

    #[test]
    fn test_no_finding_state_before_cpi() {
        let source = r#"
            fn process(accounts: &[AccountInfo]) -> ProgramResult {
                let mut data = account.try_borrow_mut_data()?;
                data[0] = 1;
                invoke(&ix, &accounts)?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag state mutation before CPI"
        );
    }
}
