use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnguardedMigrateDetector;

impl Detector for UnguardedMigrateDetector {
    fn id(&self) -> &'static str {
        "CW-010"
    }
    fn name(&self) -> &'static str {
        "unguarded-migrate-entry"
    }
    fn description(&self) -> &'static str {
        "Detects migrate handler without admin/sender check or version validation"
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
        let mut visitor = MigrateVisitor {
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
    "sender",
    "admin",
    "owner",
    "ADMIN",
    "OWNER",
    "is_admin",
    "is_owner",
    "only_admin",
    "only_owner",
    "ensure_admin",
];

const VERSION_PATTERNS: &[&str] = &[
    "version",
    "VERSION",
    "get_contract_version",
    "set_contract_version",
    "cw2 ::",
    "migrate_version",
    "assert_contract_version",
    "ensure_from_older_version",
];

struct MigrateVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for MigrateVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Only check migrate entry points
        if fn_name != "migrate" && !fn_name.starts_with("migrate_") {
            return;
        }

        // Skip test functions
        if has_attribute(&func.attrs, "test") {
            return;
        }

        let body_src = fn_body_source(func);

        // Skip empty/stub implementations (just return Ok)
        let body_trimmed: String = body_src.chars().filter(|c| !c.is_whitespace()).collect();
        if body_trimmed.len() < 60 {
            return;
        }

        let has_auth = AUTH_PATTERNS.iter().any(|p| body_src.contains(p));
        let has_version = VERSION_PATTERNS.iter().any(|p| body_src.contains(p));

        if !has_auth && !has_version {
            let line = span_to_line(&func.sig.ident.span());
            self.findings.push(Finding {
                detector_id: "CW-010".to_string(),
                name: "unguarded-migrate-entry".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                message: format!(
                    "Migrate handler '{}' has no admin/sender check or version validation",
                    fn_name
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add admin authorization check (info.sender) and/or version validation (cw2::set_contract_version) in migrate handler".to_string(),
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
        );
        UnguardedMigrateDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unguarded_migrate() {
        let source = r#"
            fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
                CONFIG.save(deps.storage, &Config { new_field: msg.new_field })?;
                STATE.update(deps.storage, |mut s| -> StdResult<_> {
                    s.migrated = true;
                    Ok(s)
                })?;
                Ok(Response::new().add_attribute("action", "migrate"))
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unguarded migrate");
        assert_eq!(findings[0].detector_id, "CW-010");
    }

    #[test]
    fn test_no_finding_with_admin_check() {
        let source = r#"
            fn migrate(deps: DepsMut, env: Env, info: MessageInfo, msg: MigrateMsg) -> StdResult<Response> {
                let admin = ADMIN.load(deps.storage)?;
                if info.sender != admin {
                    return Err(StdError::generic_err("unauthorized"));
                }
                CONFIG.save(deps.storage, &Config { new_field: msg.new_field })?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with admin/sender check"
        );
    }

    #[test]
    fn test_no_finding_with_version_check() {
        let source = r#"
            fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
                let ver = cw2 :: get_contract_version(deps.storage)?;
                set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
                CONFIG.save(deps.storage, &Config { new_field: msg.new_field })?;
                Ok(Response::new())
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag with version validation"
        );
    }
}
