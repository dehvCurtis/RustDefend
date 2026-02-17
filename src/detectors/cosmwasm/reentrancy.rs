use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct ReentrancyDetector;

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "CW-002"
    }
    fn name(&self) -> &'static str {
        "cosmwasm-reentrancy"
    }
    fn description(&self) -> &'static str {
        "Detects storage writes followed by add_message/add_submessage (CEI violation) - informational: CosmWasm is non-reentrant by design"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn confidence(&self) -> Confidence {
        Confidence::Low
    }
    fn chain(&self) -> Chain {
        Chain::CosmWasm
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ReentrancyVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct ReentrancyVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ReentrancyVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions
        if fn_name.contains("test")
            || fn_name.contains("_works")
            || fn_name.contains("_mock")
            || fn_name.contains("_should")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let body_src = fn_body_source(func);

        // Must contain both storage save and message dispatch
        if !body_src.contains(".save(") && !body_src.contains(". save (") {
            return;
        }

        let has_message = body_src.contains("add_message")
            || body_src.contains("add_submessage")
            || body_src.contains("WasmMsg");

        if !has_message {
            return;
        }

        // CosmWasm is non-reentrant by design. Only flag if IBC hooks are involved
        // (CWA-2024-007 reentrancy via ibc-hooks) or if it's a reply/submessage handler.
        let is_ibc_relevant = fn_name.contains("ibc")
            || body_src.contains("IbcMsg")
            || body_src.contains("ibc")
            || fn_name.starts_with("reply")
            || fn_name.contains("reply")
            || body_src.contains("SubMsg")
            || body_src.contains("ReplyOn");

        if !is_ibc_relevant {
            return;
        }

        // Check ordering: save before add_message
        let stmts = &func.block.stmts;
        let mut seen_save = false;

        for stmt in stmts {
            let stmt_str = stmt.to_token_stream().to_string();

            if stmt_str.contains(".save(") || stmt_str.contains(". save (") {
                seen_save = true;
            }

            if seen_save
                && (stmt_str.contains("add_message")
                    || stmt_str.contains("add_submessage")
                    || stmt_str.contains("WasmMsg :: Execute"))
            {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "CW-002".to_string(),
                    name: "cosmwasm-reentrancy".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Low,
                    message: format!(
                        "Function '{}' writes to storage before dispatching external message",
                        func.sig.ident
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "CosmWasm's actor model prevents reentrancy by design. This is informational for code organization. Consider CEI pattern if using IBC hooks".to_string(),
                    chain: Chain::CosmWasm,
                });
                return;
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
            Chain::CosmWasm,
        );
        ReentrancyDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_save_before_message_in_ibc() {
        let source = r#"
            fn ibc_packet_receive(deps: DepsMut, msg: IbcPacketReceiveMsg) -> StdResult<Response> {
                STATE.save(deps.storage, &new_state)?;
                Ok(Response::new().add_message(WasmMsg::Execute { .. }))
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect save before add_message in IBC handler"
        );
    }

    #[test]
    fn test_no_finding_non_ibc_handler() {
        let source = r#"
            fn execute_transfer(deps: DepsMut, info: MessageInfo) -> StdResult<Response> {
                STATE.save(deps.storage, &new_state)?;
                Ok(Response::new().add_message(WasmMsg::Execute { .. }))
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag non-IBC handler (CosmWasm is non-reentrant by design)"
        );
    }
}
