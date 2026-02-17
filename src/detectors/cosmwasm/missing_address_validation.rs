use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingAddressValidationDetector;

impl Detector for MissingAddressValidationDetector {
    fn id(&self) -> &'static str {
        "CW-009"
    }
    fn name(&self) -> &'static str {
        "cosmwasm-missing-addr-validation"
    }
    fn description(&self) -> &'static str {
        "Detects Addr::unchecked() usage in non-test code (address validation bypass)"
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
        let mut visitor = AddrVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct AddrVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for AddrVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions and mock/helper/setup functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || fn_name.contains("_works")
            || fn_name.contains("_mock")
            || fn_name.contains("_should")
            || fn_name.starts_with("mock_")
            || fn_name.starts_with("setup")
            || fn_name.starts_with("fixture")
            || fn_name.starts_with("helper")
            || fn_name.starts_with("create_test")
            || fn_name.starts_with("make_test")
            || fn_name.starts_with("default_")
            || fn_name.starts_with("new_test")
            || fn_name.starts_with("instantiate_test")
            || fn_name.contains("mock_deps")
            || fn_name.contains("mock_env")
            || fn_name.contains("mock_info")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        // Skip if file path suggests test/mock code
        let file_str = self.ctx.file_path.to_string_lossy();
        if file_str.contains("/testing")
            || file_str.contains("/mock")
            || file_str.contains("/helpers")
            || file_str.contains("/testutils")
            || file_str.contains("_mock.rs")
            || file_str.contains("_helpers.rs")
            || file_str.contains("test_utils")
            || file_str.contains("testing.rs")
            || file_str.contains("integration_tests")
            || file_str.contains("multitest")
        {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for Addr::unchecked usage
        if !body_src.contains("Addr :: unchecked") && !body_src.contains("Addr::unchecked") {
            // Also check source text for exact match
            let fn_source = func.to_token_stream().to_string();
            if !fn_source.contains("Addr :: unchecked") {
                return;
            }
        }

        // Check if there's also addr_validate in the same function (mixed usage is OK)
        if body_src.contains("addr_validate") {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "CW-009".to_string(),
            name: "cosmwasm-missing-addr-validation".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' uses Addr::unchecked() without addr_validate()",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Use deps.api.addr_validate(&addr)? instead of Addr::unchecked() to prevent address case-variation attacks".to_string(),
            chain: Chain::CosmWasm,
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
            Chain::CosmWasm,
            std::collections::HashMap::new(),
        );
        MissingAddressValidationDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unchecked_addr() {
        let source = r#"
            fn execute_transfer(deps: DepsMut, recipient: String) -> StdResult<Response> {
                let addr = Addr::unchecked(&recipient);
                BALANCES.save(deps.storage, &addr, &amount)?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect Addr::unchecked");
    }

    #[test]
    fn test_no_finding_with_validation() {
        let source = r#"
            fn execute_transfer(deps: DepsMut, recipient: String) -> StdResult<Response> {
                let addr = deps.api.addr_validate(&recipient)?;
                BALANCES.save(deps.storage, &addr, &amount)?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with addr_validate");
    }

    #[test]
    fn test_no_finding_in_test() {
        let source = r#"
            #[test]
            fn test_transfer() {
                let addr = Addr::unchecked("sender");
                assert_eq!(addr, expected);
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag in test functions");
    }

    #[test]
    fn test_no_finding_in_mock_function() {
        let source = r#"
            fn mock_deps() -> OwnedDeps<MockStorage> {
                let addr = Addr::unchecked("contract_addr");
                mock_dependencies()
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag mock/helper functions");
    }

    #[test]
    fn test_no_finding_in_setup_function() {
        let source = r#"
            fn setup_contract(deps: DepsMut) {
                let addr = Addr::unchecked("admin");
                CONFIG.save(deps.storage, &addr).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag setup functions");
    }
}
