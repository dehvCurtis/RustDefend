use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct CheckedArithmeticUnwrapDetector;

impl Detector for CheckedArithmeticUnwrapDetector {
    fn id(&self) -> &'static str {
        "SOL-020"
    }
    fn name(&self) -> &'static str {
        "checked-arithmetic-unwrap"
    }
    fn description(&self) -> &'static str {
        "Detects .checked_add/sub/mul/div(...).unwrap() chains that panic instead of propagating errors"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        if !ctx.source.contains("solana_program")
            && !ctx.source.contains("anchor_lang")
            && !ctx.source.contains("AccountInfo")
            && !ctx.source.contains("ProgramResult")
            && !ctx.source.contains("solana_sdk")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = CheckedUnwrapVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct CheckedUnwrapVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

const CHECKED_OPS: &[&str] = &[
    "checked_add",
    "checked_sub",
    "checked_mul",
    "checked_div",
    "checked_rem",
    "checked_pow",
    "checked_shl",
    "checked_shr",
];

impl<'ast, 'a> Visit<'ast> for CheckedUnwrapVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        if fn_name.contains("test") || has_attribute(&func.attrs, "test") {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for .checked_*(...).unwrap() patterns
        // Don't flag .checked_*(...)?  or .checked_*(...).ok_or(...)? — those propagate errors correctly
        for op in CHECKED_OPS {
            // Check for the pattern: checked_op(...).unwrap()
            // In tokenized form this may appear as: checked_add (...) . unwrap ()
            let patterns = [
                format!("{} (", op), // tokenized form
                format!("{}(", op),  // compact form
            ];

            for pattern in &patterns {
                let mut search_from = 0;
                while let Some(pos) = body_src[search_from..].find(pattern.as_str()) {
                    let abs_pos = search_from + pos;
                    // Find the matching closing paren, then look for .unwrap()
                    let after_op = &body_src[abs_pos..];

                    // Check if .unwrap() follows (within reasonable distance)
                    // Look for unwrap() within 100 chars after the checked_op call
                    let check_region = if after_op.len() > 200 {
                        &after_op[..200]
                    } else {
                        after_op
                    };

                    if (check_region.contains(". unwrap ()") || check_region.contains(".unwrap()"))
                        && !check_region.contains(". ok_or")
                        && !check_region.contains(".ok_or")
                        && !check_region.contains("?")
                    {
                        // Find the line number
                        let line = body_src[..abs_pos].matches('\n').count()
                            + span_to_line(&func.sig.ident.span());
                        self.findings.push(Finding {
                            detector_id: "SOL-020".to_string(),
                            name: "checked-arithmetic-unwrap".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            message: format!(
                                "Function '{}' calls .{}().unwrap() — use .ok_or(...)? to propagate errors instead of panicking",
                                func.sig.ident, op
                            ),
                            file: self.ctx.file_path.clone(),
                            line,
                            column: span_to_column(&func.sig.ident.span()),
                            snippet: snippet_at_line(&self.ctx.source, line),
                            recommendation: format!(
                                "Replace .{}().unwrap() with .{}().ok_or(MyError::Overflow)? to return an error instead of panicking",
                                op, op
                            ),
                            chain: Chain::Solana,
                        });
                        break; // One finding per op per function
                    }

                    search_from = abs_pos + pattern.len();
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
            std::collections::HashMap::new(),
        );
        CheckedArithmeticUnwrapDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_checked_add_unwrap() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn calculate(a: u64, b: u64) -> u64 {
                a.checked_add(b).unwrap()
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect checked_add().unwrap()");
    }

    #[test]
    fn test_detects_checked_sub_unwrap() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn calculate(a: u64, b: u64) -> u64 {
                a.checked_sub(b).unwrap()
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect checked_sub().unwrap()");
    }

    #[test]
    fn test_no_finding_with_question_mark() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn calculate(a: u64, b: u64) -> Result<u64, ProgramError> {
                let result = a.checked_add(b).ok_or(ProgramError::ArithmeticOverflow)?;
                Ok(result)
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag .checked_add(...).ok_or(...)?"
        );
    }

    #[test]
    fn test_no_finding_without_solana_markers() {
        let source = r#"
            fn calculate(a: u64, b: u64) -> u64 {
                a.checked_add(b).unwrap()
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag without Solana source markers"
        );
    }
}
