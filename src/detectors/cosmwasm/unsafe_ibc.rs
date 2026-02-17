use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnsafeIbcDetector;

impl Detector for UnsafeIbcDetector {
    fn id(&self) -> &'static str {
        "CW-008"
    }
    fn name(&self) -> &'static str {
        "unsafe-ibc-entry-points"
    }
    fn description(&self) -> &'static str {
        "Detects IBC packet handlers without channel validation or proper timeout rollback"
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
        // Check if file has ibc_channel_open (validates channels at connect time)
        let has_channel_open = ctx.source.contains("ibc_channel_open");

        let mut findings = Vec::new();
        let mut visitor = IbcVisitor {
            findings: &mut findings,
            ctx,
            has_channel_open,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const IBC_HANDLER_FUNCTIONS: &[&str] = &[
    "ibc_packet_receive",
    "ibc_packet_ack",
    "ibc_source_callback",
    "ibc_destination_callback",
];

const IBC_TIMEOUT_FUNCTIONS: &[&str] = &["ibc_packet_timeout"];

const CHANNEL_SAFE_PATTERNS: &[&str] = &[
    "channel_id",
    "dest . channel_id",
    "src . channel_id",
    "ALLOWED_CHANNEL",
    "IBC_CHANNEL",
];

const TIMEOUT_SAFE_PATTERNS: &[&str] = &[
    "refund",
    "rollback",
    "revert",
    "restore",
    "undo",
    "return_funds",
];

const TIMEOUT_STORAGE_PATTERNS: &[&str] = &[".save(", ".update(", ".remove("];

struct IbcVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    has_channel_open: bool,
}

impl<'ast, 'a> Visit<'ast> for IbcVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let body_src = fn_body_source(func);

        // Check if handler only returns error (intentional rejection)
        let body_trimmed = body_src.trim();
        if body_trimmed.contains("Err (") || body_trimmed.contains("StdError ::") {
            // Simple heuristic: if function body is small and returns error
            let non_whitespace: String = body_trimmed
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if non_whitespace.len() < 200
                && (non_whitespace.contains("Err(")
                    || non_whitespace.contains("IbcReceiveResponse::new()"))
            {
                // Very small function that just returns error or empty response
                if !non_whitespace.contains(".save(")
                    && !non_whitespace.contains(".update(")
                    && !non_whitespace.contains(".remove(")
                {
                    return;
                }
            }
        }

        // Check IBC receive/ack/callback handlers
        if IBC_HANDLER_FUNCTIONS.contains(&fn_name.as_str()) {
            // Skip if ibc_channel_open validates channels in same file
            if self.has_channel_open {
                return;
            }

            let has_channel_check = CHANNEL_SAFE_PATTERNS.iter().any(|p| body_src.contains(p));

            if !has_channel_check {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "CW-008".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    message: format!(
                        "IBC handler '{}' does not validate the source/destination channel",
                        fn_name
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Validate channel_id against an allowed list, or implement ibc_channel_open to filter channels at connection time".to_string(),
                    chain: Chain::CosmWasm,
                });
            }
        }

        // Check IBC timeout handlers
        if IBC_TIMEOUT_FUNCTIONS.contains(&fn_name.as_str()) {
            let has_rollback = TIMEOUT_SAFE_PATTERNS.iter().any(|p| body_src.contains(p));
            let has_storage_mutation = TIMEOUT_STORAGE_PATTERNS
                .iter()
                .any(|p| body_src.contains(p));

            if !has_rollback && !has_storage_mutation {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "CW-008".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    message: format!(
                        "IBC timeout handler '{}' does not perform rollback or state cleanup",
                        fn_name
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Implement rollback logic in timeout handlers to refund/revert state when IBC packets time out".to_string(),
                    chain: Chain::CosmWasm,
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
            Chain::CosmWasm,
        );
        UnsafeIbcDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_ibc_receive_without_channel_check() {
        let source = r#"
            fn ibc_packet_receive(deps: DepsMut, env: Env, msg: IbcPacketReceiveMsg) -> StdResult<IbcReceiveResponse> {
                let packet = msg.packet;
                let data: TransferMsg = from_binary(&packet.data)?;
                execute_transfer(deps, data.recipient, data.amount)?;
                Ok(IbcReceiveResponse::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect IBC receive without channel validation"
        );
        assert_eq!(findings[0].detector_id, "CW-008");
    }

    #[test]
    fn test_no_finding_with_channel_validation() {
        let source = r#"
            fn ibc_packet_receive(deps: DepsMut, env: Env, msg: IbcPacketReceiveMsg) -> StdResult<IbcReceiveResponse> {
                let packet = msg.packet;
                let channel = packet.dest.channel_id;
                if channel != IBC_CHANNEL.load(deps.storage)? {
                    return Err(StdError::generic_err("unauthorized channel"));
                }
                let data: TransferMsg = from_binary(&packet.data)?;
                execute_transfer(deps, data.recipient, data.amount)?;
                Ok(IbcReceiveResponse::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when channel validation is present"
        );
    }

    #[test]
    fn test_detects_empty_timeout_handler() {
        let source = r#"
            fn ibc_packet_timeout(deps: DepsMut, env: Env, msg: IbcPacketTimeoutMsg) -> StdResult<IbcBasicResponse> {
                Ok(IbcBasicResponse::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect empty timeout handler");
    }

    #[test]
    fn test_no_finding_timeout_with_rollback() {
        let source = r#"
            fn ibc_packet_timeout(deps: DepsMut, env: Env, msg: IbcPacketTimeoutMsg) -> StdResult<IbcBasicResponse> {
                let packet = msg.packet;
                let data: TransferMsg = from_binary(&packet.data)?;
                refund(deps, data.sender, data.amount)?;
                Ok(IbcBasicResponse::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag timeout handler with rollback"
        );
    }

    #[test]
    fn test_no_finding_with_channel_open_in_file() {
        let source = r#"
            fn ibc_channel_open(deps: DepsMut, env: Env, msg: IbcChannelOpenMsg) -> StdResult<()> {
                validate_channel(msg.channel())?;
                Ok(())
            }

            fn ibc_packet_receive(deps: DepsMut, env: Env, msg: IbcPacketReceiveMsg) -> StdResult<IbcReceiveResponse> {
                let packet = msg.packet;
                let data: TransferMsg = from_binary(&packet.data)?;
                execute_transfer(deps, data.recipient, data.amount)?;
                Ok(IbcReceiveResponse::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when ibc_channel_open validates channels"
        );
    }
}
