use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingReplyIdDetector;

impl Detector for MissingReplyIdDetector {
    fn id(&self) -> &'static str {
        "CW-011"
    }
    fn name(&self) -> &'static str {
        "missing-reply-id-validation"
    }
    fn description(&self) -> &'static str {
        "Detects reply handler not matching on msg.id, processing all submessage replies identically"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::CosmWasm
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = ReplyVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const REPLY_ID_PATTERNS: &[&str] = &[
    "msg . id",
    "msg.id",
    "reply . id",
    "reply.id",
    "REPLY_ID",
    "INSTANTIATE_REPLY",
    "EXECUTE_REPLY",
    "reply_id",
    "SubMsgResult",
    "match msg",
    "match reply",
];

struct ReplyVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for ReplyVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Only check reply entry points
        if fn_name != "reply" {
            return;
        }

        // Skip test functions
        if has_attribute(&func.attrs, "test") {
            return;
        }

        let body_src = fn_body_source(func);

        // Skip trivial implementations
        let body_trimmed: String = body_src.chars().filter(|c| !c.is_whitespace()).collect();
        if body_trimmed.len() < 50 {
            return;
        }

        let has_id_check = REPLY_ID_PATTERNS.iter().any(|p| body_src.contains(p));

        if !has_id_check {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "CW-011".to_string(),
                name: "missing-reply-id-validation".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Reply handler '{}' does not match on msg.id — all submessage replies processed identically",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Match on msg.id to distinguish between different submessage replies (e.g., match msg.id { INSTANTIATE_REPLY_ID => ..., _ => ... })".to_string(),
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
        MissingReplyIdDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_reply_without_id_check() {
        let source = r#"
            fn reply(deps: DepsMut, env: Env, msg: Reply) -> StdResult<Response> {
                let result = msg.result.into_result().map_err(StdError::generic_err)?;
                let event = result.events.iter().find(|e| e.ty == "instantiate").unwrap();
                let addr = &event.attributes[0].value;
                CHILD_CONTRACT.save(deps.storage, &deps.api.addr_validate(addr)?)?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect reply without msg.id check"
        );
        assert_eq!(findings[0].detector_id, "CW-011");
    }

    #[test]
    fn test_no_finding_with_id_match() {
        let source = r#"
            fn reply(deps: DepsMut, env: Env, msg: Reply) -> StdResult<Response> {
                match msg.id {
                    INSTANTIATE_REPLY => handle_instantiate_reply(deps, msg),
                    EXECUTE_REPLY => handle_execute_reply(deps, msg),
                    id => Err(StdError::generic_err(format!("unknown reply id: {}", id))),
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when msg.id is matched"
        );
    }

    #[test]
    fn test_no_finding_with_reply_id_constant() {
        let source = r#"
            fn reply(deps: DepsMut, env: Env, msg: Reply) -> StdResult<Response> {
                if msg.id != REPLY_ID {
                    return Err(StdError::generic_err("unexpected reply"));
                }
                let result = msg.result.into_result().map_err(StdError::generic_err)?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when reply.id is checked"
        );
    }
}
