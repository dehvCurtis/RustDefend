use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingGasCallbackDetector;

impl Detector for MissingGasCallbackDetector {
    fn id(&self) -> &'static str {
        "NEAR-012"
    }
    fn name(&self) -> &'static str {
        "missing-gas-for-callbacks"
    }
    fn description(&self) -> &'static str {
        "Detects cross-contract calls without explicit gas specification"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Near
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = GasVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const CROSS_CONTRACT_PATTERNS: &[&str] = &[
    "Promise :: new",
    "Promise::new",
    "ext_self ::",
    "ext_self::",
    "ext_contract ::",
    "ext_contract::",
    ".function_call(",
];

const GAS_PATTERNS: &[&str] = &[
    "gas (",
    "Gas (",
    "gas(",
    "Gas(",
    ".with_static_gas(",
    ".with_attached_gas(",
    ".with_unused_gas_weight(",
    "GAS_FOR_",
    "CALLBACK_GAS",
    "TGAS",
    "TGas",
    "NearGas",
    "prepaid_gas",
];

struct GasVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for GasVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        // Skip callback functions (they receive gas, don't specify it)
        if fn_name.starts_with("on_") || fn_name.ends_with("_callback") {
            return;
        }

        let body_src = fn_body_source(func);

        let has_cross_contract = CROSS_CONTRACT_PATTERNS.iter().any(|p| body_src.contains(p));
        if !has_cross_contract {
            return;
        }

        let has_gas_spec = GAS_PATTERNS.iter().any(|p| body_src.contains(p));

        if !has_gas_spec {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "NEAR-012".to_string(),
                name: "missing-gas-for-callbacks".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Function '{}' makes cross-contract calls without explicit gas specification",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Specify gas explicitly with .with_static_gas() or Gas() to prevent callbacks from running out of gas".to_string(),
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
        MissingGasCallbackDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_gas() {
        let source = r#"
            fn transfer_and_call(&mut self, receiver_id: AccountId, amount: U128) {
                self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0);
                Promise::new(receiver_id).function_call(
                    "on_transfer".to_string(),
                    json!({ "amount": amount }).to_string().into_bytes(),
                    0,
                    DEFAULT_GAS,
                );
                ext_self::on_transfer_complete(env::current_account_id());
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect missing gas specification"
        );
        assert_eq!(findings[0].detector_id, "NEAR-012");
    }

    #[test]
    fn test_no_finding_with_gas_spec() {
        let source = r#"
            fn transfer_and_call(&mut self, receiver_id: AccountId, amount: U128) {
                self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0);
                Promise::new(receiver_id).function_call(
                    "on_transfer".to_string(),
                    json!({ "amount": amount }).to_string().into_bytes(),
                    0,
                    Gas(5_000_000_000_000),
                );
                ext_self::on_transfer_complete(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with explicit gas specification"
        );
    }

    #[test]
    fn test_skips_callback_functions() {
        let source = r#"
            fn on_transfer_complete(&mut self) {
                Promise::new(env::predecessor_account_id()).function_call(
                    "finalize".to_string(),
                    vec![],
                    0,
                    DEFAULT_GAS,
                );
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should skip callback functions (on_ prefix)"
        );
    }
}
