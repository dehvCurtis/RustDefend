use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingSenderCheckDetector;

impl Detector for MissingSenderCheckDetector {
    fn id(&self) -> &'static str {
        "CW-003"
    }
    fn name(&self) -> &'static str {
        "missing-sender-check"
    }
    fn description(&self) -> &'static str {
        "Detects execute handler match arms that mutate storage without checking info.sender"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::CosmWasm
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = SenderVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct SenderVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SenderVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Only analyze execute entry points
        if !fn_name.contains("execute") {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for match on ExecuteMsg
        if !body_src.contains("ExecuteMsg") {
            return;
        }

        // Check each match arm conceptually
        // We'll look at the function body for save/update operations without sender checks
        let has_storage_mutation = body_src.contains(". save (")
            || body_src.contains(".save(")
            || body_src.contains(". update (")
            || body_src.contains(".update(")
            || body_src.contains(". remove (")
            || body_src.contains(".remove(");

        if !has_storage_mutation {
            return;
        }

        let has_sender_check = body_src.contains("info . sender")
            || body_src.contains("info.sender")
            || body_src.contains("sender");

        if !has_sender_check {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "CW-003".to_string(),
                name: "missing-sender-check".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                message: format!(
                    "Execute handler '{}' mutates storage without checking info.sender",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add `if info.sender != authorized_addr { return Err(...) }` before storage mutations".to_string(),
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
        MissingSenderCheckDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_sender() {
        let source = r#"
            fn execute_update_config(deps: DepsMut, info: MessageInfo, new_val: u64) -> StdResult<Response> {
                match msg {
                    ExecuteMsg::UpdateConfig { val } => {
                        CONFIG.save(deps.storage, &val)?;
                        Ok(Response::new())
                    }
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing sender check");
    }

    #[test]
    fn test_no_finding_with_sender() {
        let source = r#"
            fn execute_update_config(deps: DepsMut, info: MessageInfo, new_val: u64) -> StdResult<Response> {
                match msg {
                    ExecuteMsg::UpdateConfig { val } => {
                        if info.sender != owner {
                            return Err(StdError::generic_err("unauthorized"));
                        }
                        CONFIG.save(deps.storage, &val)?;
                        Ok(Response::new())
                    }
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with sender check");
    }
}
