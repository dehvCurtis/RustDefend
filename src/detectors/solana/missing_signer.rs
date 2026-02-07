use syn::visit::Visit;
use syn::{FnArg, ItemFn};
use quote::ToTokens;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingSignerDetector;

impl Detector for MissingSignerDetector {
    fn id(&self) -> &'static str { "SOL-001" }
    fn name(&self) -> &'static str { "missing-signer-check" }
    fn description(&self) -> &'static str {
        "Detects functions accepting AccountInfo without verifying is_signer"
    }
    fn severity(&self) -> Severity { Severity::Critical }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn chain(&self) -> Chain { Chain::Solana }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = SignerVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct SignerVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for SignerVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let body_src = fn_body_source(func);

        // Skip if this uses Anchor's Signer<'info> or Account<'info, T> patterns
        let fn_src = func.to_token_stream().to_string();
        if fn_src.contains("Signer") || fn_src.contains("Context <") || fn_src.contains("Context<") {
            return;
        }

        // Look for AccountInfo parameters
        let mut unchecked_params: Vec<String> = Vec::new();

        for arg in &func.sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                let type_str = pat_type.ty.to_token_stream().to_string();
                if type_str.contains("AccountInfo") {
                    // Skip slice types like &[AccountInfo] - these are
                    // the standard process_instruction array parameter,
                    // not individual account references
                    if type_str.contains('[') || type_str.contains("Vec") {
                        continue;
                    }

                    // Get the parameter name
                    let param_name = pat_type.pat.to_token_stream().to_string();

                    // Skip common non-signer parameter names (iterators, program ids)
                    let param_lower = param_name.to_lowercase();
                    if param_lower.contains("program")
                        || param_lower.contains("system")
                        || param_lower.contains("rent")
                        || param_lower.contains("clock")
                        || param_lower.contains("token")
                        || param_lower.contains("mint")
                        || param_lower.contains("metadata")
                        || param_lower.contains("associated")
                    {
                        continue;
                    }

                    unchecked_params.push(param_name);
                }
            }
        }

        if unchecked_params.is_empty() {
            return;
        }

        // Check if body verifies is_signer
        let has_signer_check = body_src.contains("is_signer")
            || body_src.contains("has_signer");

        // Check if the function does any state mutations
        // Note: lamports() alone is a read-only getter;
        // only borrow_mut on lamports is a mutation
        let has_mutations = body_src.contains("serialize")
            || body_src.contains("try_borrow_mut")
            || body_src.contains("borrow_mut")
            || body_src.contains("invoke");

        // Emit a single finding per function (not per param) to avoid noise
        if !has_signer_check && has_mutations {
            let line = span_to_line(&func.sig.ident.span());
            let params_str = if unchecked_params.len() == 1 {
                format!("'{}'", unchecked_params[0])
            } else {
                unchecked_params.iter()
                    .map(|p| format!("'{}'", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            self.findings.push(Finding {
                detector_id: "SOL-001".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                message: format!(
                    "Function '{}' accepts AccountInfo {} without verifying is_signer",
                    func.sig.ident, params_str
                ),
                file: self.ctx.file_path.clone(),
                line,
                column: span_to_column(&func.sig.ident.span()),
                snippet: snippet_at_line(&self.ctx.source, line),
                recommendation: "Add `if !account.is_signer { return Err(...) }` check, or use Anchor's `Signer<'info>` type".to_string(),
                chain: Chain::Solana,
            });
        }
        // Don't recurse into nested functions
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
        );
        MissingSignerDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_signer() {
        let source = r#"
            fn process_transfer(account: &AccountInfo, dest: &AccountInfo) {
                let mut data = account.try_borrow_mut_data().unwrap();
                data.serialize(&mut *dest.try_borrow_mut_data().unwrap()).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing signer check");
        assert_eq!(findings[0].detector_id, "SOL-001");
    }

    #[test]
    fn test_no_finding_with_signer_check() {
        let source = r#"
            fn process_transfer(account: &AccountInfo, dest: &AccountInfo) {
                if !account.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                let mut data = account.try_borrow_mut_data().unwrap();
                data.serialize(&mut *dest.try_borrow_mut_data().unwrap()).unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag when is_signer is checked");
    }

    #[test]
    fn test_no_finding_account_info_slice() {
        let source = r#"
            fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
                let account_iter = &mut accounts.iter();
                let src = next_account_info(account_iter)?;
                invoke(&ix, accounts)?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag &[AccountInfo] slice parameter");
    }

    #[test]
    fn test_no_finding_anchor_signer() {
        let source = r#"
            fn process_transfer(ctx: Context<Transfer>) {
                let data = ctx.accounts.from.try_borrow_mut_data().unwrap();
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag Anchor Context pattern");
    }
}
