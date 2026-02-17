use quote::ToTokens;
use syn::visit::Visit;
use syn::{Pat, Stmt};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct ErrorHandlingDetector;

impl Detector for ErrorHandlingDetector {
    fn id(&self) -> &'static str {
        "INK-008"
    }
    fn name(&self) -> &'static str {
        "ink-result-suppression"
    }
    fn description(&self) -> &'static str {
        "Detects `let _ = expr` where expr returns Result (error suppression)"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Require ink!-specific source markers to avoid cross-chain FPs
        if !ctx.source.contains("#[ink(")
            && !ctx.source.contains("#[ink::")
            && !ctx.source.contains("ink_storage")
            && !ctx.source.contains("ink_env")
            && !ctx.source.contains("ink_lang")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = ErrorVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ErrorVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ErrorVisitor<'a> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if let Stmt::Local(local) = stmt {
            if let Pat::Wild(_) = &local.pat {
                if let Some(init) = &local.init {
                    let expr_str = init.expr.to_token_stream().to_string();

                    // Heuristic: check if expression likely returns Result
                    let likely_result = expr_str.contains("try_")
                        || expr_str.contains("send")
                        || expr_str.contains("transfer")
                        || expr_str.contains("invoke")
                        || expr_str.contains("call")
                        || expr_str.contains("execute")
                        || expr_str.contains("save")
                        || expr_str.contains("write");

                    // Skip common non-Result patterns that match above heuristics
                    let is_false_positive = expr_str.contains("callback")
                        || expr_str.contains("channel")
                        || expr_str.contains("to_string")
                        || expr_str.contains("writeln")
                        || expr_str.contains("write !")
                        || expr_str.contains("write!")
                        || expr_str.contains("println")
                        || expr_str.contains("eprintln")
                        // Skip if the assignment is used for signaling (e.g., let _ = tx.send())
                        // which is an intentional pattern
                        || expr_str.contains("tx .")
                        || expr_str.contains("sender .");

                    if likely_result && !is_false_positive {
                        let line = span_to_line(&local.let_token.span);
                        self.findings.push(Finding {
                            detector_id: "INK-008".to_string(),
                            name: "ink-result-suppression".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            message: format!(
                                "Result of '{}' is discarded with `let _ = ...`",
                                truncate_str(&expr_str, 60)
                            ),
                            file: self.ctx.file_path.clone(),
                            line,
                            column: 1,
                            snippet: snippet_at_line(&self.ctx.source, line),
                            recommendation: "Handle the Result with `?` operator or explicit error handling instead of discarding it".to_string(),
                            chain: Chain::Ink,
                        });
                    }
                }
            }
        }

        syn::visit::visit_stmt(self, stmt);
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
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
            Chain::Ink,
            std::collections::HashMap::new(),
        );
        ErrorHandlingDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_suppressed_result() {
        let source = r#"
            #[ink(message)]
            fn send_tokens(&mut self) {
                let _ = self.env().transfer(dest, amount);
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect suppressed Result");
    }

    #[test]
    fn test_no_finding_handled() {
        let source = r#"
            fn send_tokens(&mut self) -> Result<(), Error> {
                self.env().transfer(dest, amount)?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag properly handled Result"
        );
    }
}
