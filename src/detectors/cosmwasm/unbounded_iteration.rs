use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnboundedIterationDetector;

impl Detector for UnboundedIterationDetector {
    fn id(&self) -> &'static str {
        "CW-007"
    }
    fn name(&self) -> &'static str {
        "unbounded-iteration"
    }
    fn description(&self) -> &'static str {
        "Detects .range()/.iter() without .take() in execute handlers"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::CosmWasm
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = IterVisitor {
            findings: &mut findings,
            ctx,
            in_execute: false,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct IterVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    in_execute: bool,
}

impl<'ast, 'a> Visit<'ast> for IterVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();
        let is_execute = fn_name.starts_with("execute") || fn_name.starts_with("reply");

        // Skip test functions that happen to start with entry point names
        let is_test = fn_name.contains("test")
            || fn_name.contains("_works")
            || fn_name.contains("_mock")
            || fn_name.contains("_should")
            || has_attribute(&func.attrs, "test");

        if is_execute && !is_test {
            self.in_execute = true;
            // Check for range/iter without take at the function level
            let body_src = fn_body_source(func);

            if (body_src.contains(".range(") || body_src.contains(". range ("))
                && !body_src.contains(".take(")
                && !body_src.contains(". take (")
            {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "CW-007".to_string(),
                    name: "unbounded-iteration".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    message: format!(
                        "Function '{}' uses .range() without .take() bound",
                        fn_name
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Add .take(LIMIT) to prevent unbounded iteration that could exceed gas limits".to_string(),
                    chain: Chain::CosmWasm,
                });
            }

            syn::visit::visit_item_fn(self, func);
            self.in_execute = false;
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
            Chain::CosmWasm,
            std::collections::HashMap::new(),
        );
        UnboundedIterationDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unbounded_range() {
        let source = r#"
            fn execute_distribute(deps: DepsMut) -> StdResult<Response> {
                let items: Vec<_> = BALANCES.range(deps.storage, None, None, Order::Ascending).collect::<StdResult<Vec<_>>>()?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unbounded range");
    }

    #[test]
    fn test_no_finding_with_take() {
        let source = r#"
            fn execute_distribute(deps: DepsMut) -> StdResult<Response> {
                let items: Vec<_> = BALANCES.range(deps.storage, None, None, Order::Ascending).take(100).collect::<StdResult<Vec<_>>>()?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with .take()");
    }
}
