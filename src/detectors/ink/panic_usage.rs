use quote::ToTokens;
use syn::visit::Visit;
use syn::{ExprMethodCall, ImplItemFn, Macro};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct PanicUsageDetector;

impl Detector for PanicUsageDetector {
    fn id(&self) -> &'static str {
        "INK-007"
    }
    fn name(&self) -> &'static str {
        "ink-panic-usage"
    }
    fn description(&self) -> &'static str {
        "Detects unwrap(), expect(), panic!() in ink message/constructor functions"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = PanicVisitor {
            findings: &mut findings,
            ctx,
            current_fn: None,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct PanicVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    current_fn: Option<String>,
}

impl<'ast, 'a> Visit<'ast> for PanicVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let has_ink_attr = method.attrs.iter().any(|attr| {
            let tokens = attr.meta.to_token_stream().to_string();
            tokens.contains("ink") && (tokens.contains("message") || tokens.contains("constructor"))
        });

        if has_ink_attr {
            self.current_fn = Some(method.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, method);
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
            // Skip checked_*.unwrap() - the checked_ already guards against overflow
            // e.g., self.value.checked_add(delta).unwrap() is safe arithmetic
            let receiver_src = call.receiver.to_token_stream().to_string();
            if receiver_src.contains("checked_") {
                syn::visit::visit_expr_method_call(self, call);
                return;
            }

            let line = span_to_line(&call.method.span());
            self.findings.push(Finding {
                detector_id: "INK-007".to_string(),
                name: "ink-panic-usage".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "{}() used in ink! message/constructor '{}'",
                    method,
                    self.current_fn.as_ref().unwrap()
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&call.method.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: format!(
                    "Replace .{}() with proper error handling using Result return type",
                    method
                ),
                chain: Chain::Ink,
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
            if let Some(seg) = mac.path.segments.first() {
                let line = span_to_line(&seg.ident.span());
                self.findings.push(Finding {
                    detector_id: "INK-007".to_string(),
                    name: "ink-panic-usage".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: format!(
                        "{}!() used in ink! message/constructor '{}'",
                        path_str,
                        self.current_fn.as_ref().unwrap()
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&seg.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Return a proper error instead of panicking in ink! messages"
                        .to_string(),
                    chain: Chain::Ink,
                });
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
            Chain::Ink,
            std::collections::HashMap::new(),
        );
        PanicUsageDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unwrap_in_message() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn get_value(&self) -> u32 {
                    self.map.get(&key).unwrap()
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unwrap in ink message");
    }

    #[test]
    fn test_no_finding_checked_unwrap() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn inc_by(&mut self, delta: u64) {
                    self.value = self.value.checked_add(delta).unwrap();
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag checked_add().unwrap()"
        );
    }

    #[test]
    fn test_no_finding_in_helper() {
        let source = r#"
            impl MyContract {
                fn helper(&self) -> u32 {
                    self.map.get(&key).unwrap()
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag unwrap in helper");
    }
}
