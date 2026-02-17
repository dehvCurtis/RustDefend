use quote::ToTokens;
use syn::visit::Visit;
use syn::ImplItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnboundedStorageDetector;

impl Detector for UnboundedStorageDetector {
    fn id(&self) -> &'static str {
        "INK-005"
    }
    fn name(&self) -> &'static str {
        "ink-unbounded-storage"
    }
    fn description(&self) -> &'static str {
        "Detects unbounded Vec push or Mapping insert without length check"
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
        let mut findings = Vec::new();
        let mut visitor = StorageVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct StorageVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for StorageVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        let has_ink_message = method.attrs.iter().any(|attr| {
            let tokens = attr.meta.to_token_stream().to_string();
            tokens.contains("ink") && (tokens.contains("message") || tokens.contains("constructor"))
        });

        if has_ink_message {
            let body_src = method.block.to_token_stream().to_string();

            // Check for .push() without length check
            if body_src.contains(".push(") || body_src.contains(". push (") {
                let has_len_check = body_src.contains(".len()")
                    || body_src.contains("len ()")
                    || body_src.contains("MAX_")
                    || body_src.contains("max_");

                if !has_len_check {
                    let line = span_to_line(&method.sig.ident.span());
                    self.findings.push(Finding {
                        detector_id: "INK-005".to_string(),
                        name: "ink-unbounded-storage".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        message: format!(
                            "Method '{}' pushes to Vec without bounds check",
                            method.sig.ident
                        ),
                        file: self.ctx.file_path.clone(),
                        line,
                        column: span_to_column(&method.sig.ident.span()),
                        snippet: snippet_at_line(&self.ctx.source, line),
                        recommendation: "Add a length check before pushing to prevent unbounded storage growth (DoS risk)".to_string(),
                        chain: Chain::Ink,
                    });
                }
            }

            // Check for .insert() on Mapping without bounds
            if body_src.contains(".insert(") || body_src.contains(". insert (") {
                let has_bounds = body_src.contains(".len()")
                    || body_src.contains("contains")
                    || body_src.contains("MAX_")
                    || body_src.contains("max_");

                // Skip well-known ERC-20/ERC-721 standard methods where Mapping
                // insertions are bounded by design (one entry per caller/owner)
                let method_name = method.sig.ident.to_string();
                let is_standard_pattern = method_name == "approve"
                    || method_name == "transfer"
                    || method_name == "transfer_from"
                    || method_name == "set_approval_for_all"
                    || method_name.contains("_approve")
                    || method_name.contains("set_");

                if !has_bounds && !is_standard_pattern {
                    let line = span_to_line(&method.sig.ident.span());
                    self.findings.push(Finding {
                        detector_id: "INK-005".to_string(),
                        name: "ink-unbounded-storage".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        message: format!(
                            "Method '{}' inserts into Mapping without bounds check",
                            method.sig.ident
                        ),
                        file: self.ctx.file_path.clone(),
                        line,
                        column: span_to_column(&method.sig.ident.span()),
                        snippet: snippet_at_line(&self.ctx.source, line),
                        recommendation: "Consider adding bounds checks or requiring storage deposits for unbounded Mapping growth".to_string(),
                        chain: Chain::Ink,
                    });
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
            Chain::Ink,
            std::collections::HashMap::new(),
        );
        UnboundedStorageDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unbounded_push() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn add_item(&mut self, item: u32) {
                    self.items.push(item);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unbounded push");
    }

    #[test]
    fn test_no_finding_with_len_check() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn add_item(&mut self, item: u32) {
                    assert!(self.items.len() < MAX_ITEMS);
                    self.items.push(item);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with length check");
    }
}
