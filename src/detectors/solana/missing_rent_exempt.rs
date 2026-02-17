use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingRentExemptDetector;

impl Detector for MissingRentExemptDetector {
    fn id(&self) -> &'static str {
        "SOL-011"
    }
    fn name(&self) -> &'static str {
        "missing-rent-exempt"
    }
    fn description(&self) -> &'static str {
        "Detects create_account calls without rent-exemption checks"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = RentVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct RentVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for RentVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();
        if fn_name.starts_with("test_") || fn_name.contains("_test") {
            return;
        }

        let body_src = fn_body_source(func);

        // Check for account creation patterns
        let has_create = body_src.contains("create_account") || body_src.contains("CreateAccount");

        if !has_create {
            return;
        }

        // Check for rent exemption patterns
        let has_rent_check = body_src.contains("Rent")
            || body_src.contains("rent")
            || body_src.contains("minimum_balance")
            || body_src.contains("exempt");

        // Also accept Anchor's init constraint (handled automatically)
        if has_rent_check || body_src.contains("init") {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "SOL-011".to_string(),
            name: "missing-rent-exempt".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' creates account without rent-exemption check",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation:
                "Use Rent::get()?.minimum_balance(space) to ensure accounts are rent-exempt"
                    .to_string(),
            chain: Chain::Solana,
        });
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
            Chain::Solana,
            std::collections::HashMap::new(),
        );
        MissingRentExemptDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_rent_check() {
        let source = r#"
            fn initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let ix = system_instruction::create_account(
                    payer.key, new_account.key, lamports, space as u64, program_id,
                );
                invoke(&ix, &[payer.clone(), new_account.clone()])?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing rent check");
    }

    #[test]
    fn test_no_finding_with_rent_check() {
        let source = r#"
            fn initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let rent = Rent::get()?;
                let lamports = rent.minimum_balance(space);
                let ix = system_instruction::create_account(
                    payer.key, new_account.key, lamports, space as u64, program_id,
                );
                invoke(&ix, &[payer.clone(), new_account.clone()])?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with rent check");
    }
}
