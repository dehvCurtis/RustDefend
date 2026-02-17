use quote::ToTokens;
use syn::visit::Visit;
use syn::{ExprMethodCall, ItemFn, Macro};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct ImproperErrorDetector;

impl Detector for ImproperErrorDetector {
    fn id(&self) -> &'static str {
        "CW-006"
    }
    fn name(&self) -> &'static str {
        "improper-error-handling"
    }
    fn description(&self) -> &'static str {
        "Detects unwrap(), expect(), panic!() in CosmWasm entry points"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::CosmWasm
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ErrorVisitor {
            findings: &mut findings,
            ctx,
            current_fn: None,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const ENTRY_POINTS: &[&str] = &[
    "execute",
    "instantiate",
    "query",
    "reply",
    "migrate",
    "sudo",
];

struct ErrorVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    current_fn: Option<String>,
}

impl<'ast, 'a> Visit<'ast> for ErrorVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();
        let is_entry = ENTRY_POINTS.iter().any(|ep| fn_name.starts_with(ep));

        // Skip test functions that happen to start with entry point names
        // e.g., "execute_works", "instantiate_test", "query_balance_test"
        let is_test = fn_name.contains("test")
            || fn_name.contains("_works")
            || fn_name.contains("_mock")
            || fn_name.contains("_should")
            || has_attribute(&func.attrs, "test");

        if is_entry && !is_test {
            self.current_fn = Some(fn_name);
            syn::visit::visit_item_fn(self, func);
            self.current_fn = None;
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if self.current_fn.is_none() {
            syn::visit::visit_expr_method_call(self, call);
            return;
        }

        let method = call.method.to_string();
        if method == "unwrap" || method == "expect" {
            let line = span_to_line(&call.method.span());
            self.findings.push(Finding {
                detector_id: "CW-006".to_string(),
                name: "improper-error-handling".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "{}() used in entry point '{}'",
                    method,
                    self.current_fn.as_ref().unwrap()
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&call.method.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: format!(
                    "Replace .{}() with proper error handling using `?` operator or `.map_err()`",
                    method
                ),
                chain: Chain::CosmWasm,
            });
        }

        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if self.current_fn.is_none() {
            return;
        }

        let path_str = mac.path.to_token_stream().to_string();
        if path_str == "panic" || path_str == "todo" || path_str == "unimplemented" {
            let line = span_to_line(&mac.path.segments.first().unwrap().ident.span());
            self.findings.push(Finding {
                detector_id: "CW-006".to_string(),
                name: "improper-error-handling".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "{}!() used in entry point '{}'",
                    path_str,
                    self.current_fn.as_ref().unwrap()
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&mac.path.segments.first().unwrap().ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation:
                    "Return a proper error instead of panicking in contract entry points"
                        .to_string(),
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
            std::collections::HashMap::new(),
        );
        ImproperErrorDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unwrap_in_execute() {
        let source = r#"
            fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
                let val: u64 = some_result.unwrap();
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unwrap in execute");
    }

    #[test]
    fn test_no_finding_in_test_fn() {
        let source = r#"
            fn instantiate_works() {
                let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag unwrap in test-like functions"
        );
    }

    #[test]
    fn test_no_finding_in_helper() {
        let source = r#"
            fn helper_function() -> u64 {
                some_result.unwrap()
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag unwrap in helper functions"
        );
    }
}
