use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UncheckedResponseDetector;

impl Detector for UncheckedResponseDetector {
    fn id(&self) -> &'static str { "CW-005" }
    fn name(&self) -> &'static str { "unchecked-query-response" }
    fn description(&self) -> &'static str {
        "Detects query responses used without validation"
    }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn chain(&self) -> Chain { Chain::CosmWasm }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ResponseVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ResponseVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ResponseVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Look for querier usage
        if !body_src.contains("querier") && !body_src.contains("query_wasm") {
            return;
        }

        // Check for direct query response usage without validation
        let has_query = body_src.contains(".query(")
            || body_src.contains("query_wasm_smart");

        if !has_query {
            return;
        }

        // Check if response is validated
        let has_validation = body_src.contains("ensure!")
            || body_src.contains("assert!")
            || body_src.contains("if ")
            || body_src.contains("match ")
            || body_src.contains(">")
            || body_src.contains("<")
            || body_src.contains("== ");

        if !has_validation {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "CW-005".to_string(),
                severity: Severity::High,
                confidence: Confidence::Low,
                message: format!(
                    "Function '{}' uses query response without validation",
                    func.sig.ident
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Validate query responses before using them (check bounds, expected values, etc.)".to_string(),
                chain: Chain::CosmWasm,
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
            Chain::CosmWasm,
        );
        UncheckedResponseDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unchecked_response() {
        let source = r#"
            fn get_price(deps: Deps) -> StdResult<Uint128> {
                let price: PriceResponse = deps.querier.query_wasm_smart(oracle, &msg)?;
                Ok(price.amount)
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unchecked query response");
    }

    #[test]
    fn test_no_finding_with_validation() {
        let source = r#"
            fn get_price(deps: Deps) -> StdResult<Uint128> {
                let price: PriceResponse = deps.querier.query_wasm_smart(oracle, &msg)?;
                if price.amount > Uint128::zero() {
                    Ok(price.amount)
                } else {
                    Err(StdError::generic_err("invalid price"))
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with validation");
    }
}
