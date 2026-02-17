use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct SylviaPatternDetector;

impl Detector for SylviaPatternDetector {
    fn id(&self) -> &'static str {
        "CW-012"
    }
    fn name(&self) -> &'static str {
        "sylvia-pattern-issues"
    }
    fn description(&self) -> &'static str {
        "Detects Sylvia contract methods with #[sv::msg(exec)] attribute missing authorization checks"
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
        let mut visitor = SylviaVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const AUTH_PATTERNS: &[&str] = &[
    "info . sender",
    "info.sender",
    "deps . api . addr_validate",
    "deps.api.addr_validate",
    "ensure !",
    "ensure!",
    "require !",
    "require!",
    "assert !",
    "assert!",
    "admin",
    "owner",
];

const WRITE_PATTERNS: &[&str] = &[
    ".save(",
    ". save (",
    ".update(",
    ". update (",
    ".remove(",
    ". remove (",
];

struct SylviaVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SylviaVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Check if function has #[sv::msg(exec)] attribute
        let has_sv_exec = func.attrs.iter().any(|attr| {
            let tokens = attr.meta.to_token_stream().to_string();
            tokens.contains("sv :: msg (exec)") || tokens.contains("sv::msg(exec)")
        });

        if !has_sv_exec {
            return;
        }

        let body_src = fn_body_source(func);

        // Skip functions that only read (no storage writes)
        let has_write = WRITE_PATTERNS.iter().any(|p| body_src.contains(p));
        if !has_write {
            return;
        }

        // Check for authorization patterns
        let has_auth = AUTH_PATTERNS.iter().any(|p| body_src.contains(p));

        if !has_auth {
            let fn_name = func.sig.ident.to_string();
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "CW-012".to_string(),
                name: "sylvia-pattern-issues".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Sylvia exec method '{}' has storage writes but no authorization check",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add authorization check (e.g., ensure!(info.sender == admin)) to Sylvia exec method before state mutations".to_string(),
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
        SylviaPatternDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_exec_without_auth() {
        let source = r#"
            #[sv::msg(exec)]
            fn update_config(&self, ctx: ExecCtx, new_val: u64) -> StdResult<Response> {
                self.config.save(ctx.deps.storage, &Config { val: new_val })?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect exec method without auth check");
        assert_eq!(findings[0].detector_id, "CW-012");
    }

    #[test]
    fn test_no_finding_with_sender_check() {
        let source = r#"
            #[sv::msg(exec)]
            fn update_config(&self, ctx: ExecCtx, info: MessageInfo, new_val: u64) -> StdResult<Response> {
                if info.sender != self.admin {
                    return Err(StdError::generic_err("unauthorized"));
                }
                self.config.save(ctx.deps.storage, &Config { val: new_val })?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag exec method with sender check");
    }
}
