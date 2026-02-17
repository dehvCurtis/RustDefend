use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct Cw2MigrationDetector;

impl Detector for Cw2MigrationDetector {
    fn id(&self) -> &'static str {
        "CW-013"
    }
    fn name(&self) -> &'static str {
        "cw2-migration-issues"
    }
    fn description(&self) -> &'static str {
        "Detects cosmwasm-std 2.x API misuse patterns in migration code"
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
        // Skip if file doesn't contain cosmwasm markers or migrate
        if !ctx.source.contains("cosmwasm") && !ctx.source.contains("migrate") {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = MigrationVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const DEPRECATED_PATTERNS: &[(&str, &str)] = &[
    ("from_binary", "from_json"),
    ("to_binary", "to_json_binary"),
];

struct MigrationVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for MigrationVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Only check migrate entry points or migration-related functions
        if fn_name != "migrate" && !fn_name.starts_with("migrate_") {
            return;
        }

        // Skip test functions
        if has_attribute(&func.attrs, "test") {
            return;
        }

        let body_src = fn_body_source(func);

        // Check for deprecated API patterns
        for (deprecated, replacement) in DEPRECATED_PATTERNS {
            // Match the deprecated pattern but not if it's already the replacement
            let has_deprecated = body_src.contains(deprecated)
                && !body_src.contains(replacement);

            if has_deprecated {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "CW-013".to_string(),
                    name: "cw2-migration-issues".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    message: format!(
                        "Migrate function '{}' uses deprecated '{}' instead of '{}'",
                        fn_name, deprecated, replacement
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Update to cosmwasm-std 2.x API: use from_json/to_json_binary instead of from_binary/to_binary, and ensure set_contract_version is called in migrate".to_string(),
                    chain: Chain::CosmWasm,
                });
            }
        }

        // Check for missing set_contract_version call — only if the file
        // already uses cw2 (imports it or references it), indicating the project
        // uses versioned migrations. Otherwise this is too noisy.
        let file_uses_cw2 = self.ctx.source.contains("cw2")
            || self.ctx.source.contains("set_contract_version")
            || self.ctx.source.contains("get_contract_version")
            || self.ctx.source.contains("CONTRACT_VERSION");

        if file_uses_cw2 {
            let has_set_version = body_src.contains("set_contract_version")
                || body_src.contains("set _ contract _ version");

            if !has_set_version {
                let line = span_to_line(&func.sig.ident.span());
                self.findings.push(Finding {
                    detector_id: "CW-013".to_string(),
                    name: "cw2-migration-issues".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    message: format!(
                        "Migrate function '{}' does not call cw2::set_contract_version",
                        fn_name
                    ),
                    file: self.ctx.file_path.clone(),
                    line,
                    column: span_to_column(&func.sig.ident.span()),
                    snippet: snippet_at_line(&self.ctx.source, line),
                    recommendation: "Ensure set_contract_version is called in migrate to track contract versions across upgrades".to_string(),
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
            std::collections::HashMap::new(),
        );
        Cw2MigrationDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_deprecated_from_binary() {
        let source = r#"
            use cosmwasm_std::from_binary;
            #[entry_point]
            fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
                let data: OldState = from_binary(&msg.data)?;
                CONFIG.save(deps.storage, &data.into())?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect deprecated from_binary usage");
        assert!(
            findings.iter().any(|f| f.message.contains("from_binary")),
            "Should mention from_binary in finding"
        );
    }

    #[test]
    fn test_no_finding_with_modern_api() {
        let source = r#"
            use cosmwasm_std::from_json;
            #[entry_point]
            fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
                let data: OldState = from_json(&msg.data)?;
                set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
                CONFIG.save(deps.storage, &data.into())?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag modern cosmwasm-std 2.x API usage");
    }
}
