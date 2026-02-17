use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnsafePdaSeedsDetector;

impl Detector for UnsafePdaSeedsDetector {
    fn id(&self) -> &'static str {
        "SOL-010"
    }
    fn name(&self) -> &'static str {
        "unsafe-pda-seeds"
    }
    fn description(&self) -> &'static str {
        "Detects PDA seeds without user-specific components (collision risk)"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = PdaVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct PdaVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for PdaVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();
        if fn_name.starts_with("test_") || fn_name.contains("_test") {
            return;
        }

        // Skip Anchor codegen/macro infrastructure functions
        let fn_lower = fn_name.to_lowercase();
        if fn_lower.contains("constraint")
            || fn_lower.contains("__anchor")
            || fn_lower.starts_with("_")
            || fn_lower.contains("seeds_with_nonce")
            || fn_lower.contains("create_with_seed")
        {
            return;
        }

        // Skip if file path suggests Anchor codegen
        let file_str = self.ctx.file_path.to_string_lossy();
        if file_str.contains("/generated/")
            || file_str.contains("/codegen/")
            || file_str.contains("constraints.rs")
            || file_str.contains("__cpi.rs")
            || file_str.contains("__client.rs")
        {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for find_program_address or create_program_address calls
        if !body_src.contains("find_program_address")
            && !body_src.contains("create_program_address")
        {
            return;
        }

        // Check each line for PDA seed construction
        for (i, line) in self.ctx.source.lines().enumerate() {
            let line_num = i + 1;
            if !line.contains("find_program_address") && !line.contains("create_program_address") {
                continue;
            }

            // Get the seeds context — look at surrounding lines for the &[...] seed array
            let context = get_context_lines(&self.ctx.source, line_num, 5);

            // Check if seeds contain dynamic components
            let has_dynamic_seed = context.contains(".key()")
                || context.contains(".key ()")
                || context.contains("as_ref()")
                || context.contains("as_ref ()")
                || context.contains(".to_bytes()")
                || context.contains("to_le_bytes")
                || context.contains("to_be_bytes")
                || context.contains("user")
                || context.contains("authority")
                || context.contains("owner")
                || context.contains("mint")
                || context.contains("signer")
                || context.contains("payer")
                || context.contains("wallet")
                || context.contains("sender")
                || context.contains("recipient");

            // Skip intentionally global/singleton PDAs
            let is_global_pda = context.contains("b\"config\"")
                || context.contains("b\"metadata\"")
                || context.contains("b\"state\"")
                || context.contains("b\"global\"")
                || context.contains("b\"treasury\"")
                || context.contains("b\"vault\"")
                || context.contains("b\"admin\"")
                || context.contains("b\"program\"")
                || context.contains("CONFIG_SEED")
                || context.contains("STATE_SEED")
                || context.contains("GLOBAL_SEED");

            if !has_dynamic_seed && !is_global_pda {
                self.findings.push(Finding {
                    detector_id: "SOL-010".to_string(),
                    name: "unsafe-pda-seeds".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    message: format!(
                        "PDA seeds in '{}' may lack user-specific components (collision risk)",
                        fn_name
                    ),
                    file: self.ctx.file_path.clone(),
                    line: line_num,
                    column: 1,
                    snippet: line.trim().to_string(),
                    recommendation: "Include user-specific seeds (e.g., user.key().as_ref()) to prevent PDA collisions. If this is an intentionally global PDA, use a named seed constant".to_string(),
                    chain: Chain::Solana,
                });
            }
        }

        syn::visit::visit_item_fn(self, func);
    }
}

fn get_context_lines(source: &str, line: usize, window: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = line.saturating_sub(window + 1);
    let end = (line + window).min(lines.len());
    lines[start..end].join("\n")
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
        UnsafePdaSeedsDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_static_seeds() {
        let source = r#"
            fn create_escrow(program_id: &Pubkey) {
                let (pda, bump) = Pubkey::find_program_address(&[b"escrow"], program_id);
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect static-only PDA seeds");
    }

    #[test]
    fn test_no_finding_global_pda() {
        let source = r#"
            fn get_config(program_id: &Pubkey) {
                let (pda, bump) = Pubkey::find_program_address(&[b"config"], program_id);
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag intentionally global PDAs like config"
        );
    }

    #[test]
    fn test_no_finding_with_user_key() {
        let source = r#"
            fn create_vault(program_id: &Pubkey, user: &Pubkey) {
                let (pda, bump) = Pubkey::find_program_address(
                    &[b"vault", user.key().as_ref()], program_id
                );
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag seeds with user key");
    }
}
