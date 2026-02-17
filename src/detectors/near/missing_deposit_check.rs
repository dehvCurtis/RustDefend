use quote::ToTokens;
use syn::visit::Visit;
use syn::ImplItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingDepositCheckDetector;

impl Detector for MissingDepositCheckDetector {
    fn id(&self) -> &'static str {
        "NEAR-010"
    }
    fn name(&self) -> &'static str {
        "missing-deposit-check"
    }
    fn description(&self) -> &'static str {
        "Detects #[payable] methods that don't check env::attached_deposit()"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Near
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // Require NEAR-specific source markers to avoid cross-chain FPs
        if !ctx.source.contains("near_sdk")
            && !ctx.source.contains("near_contract_standards")
            && !ctx.source.contains("#[near_bindgen]")
            && !ctx.source.contains("#[near(")
            && !ctx.source.contains("env::predecessor_account_id")
            && !ctx.source.contains("env::signer_account_id")
            && !ctx.source.contains("Promise::new")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = DepositVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct DepositVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for DepositVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        // Check for #[payable] attribute
        let has_payable = has_attribute(&method.attrs, "payable");

        if !has_payable {
            return;
        }

        let body_src = method.block.to_token_stream().to_string();

        // Check if function references attached_deposit
        let checks_deposit = body_src.contains("attached_deposit")
            || body_src.contains("attached_deposit ()")
            || body_src.contains("attached_deposit()");

        if checks_deposit {
            return;
        }

        let fn_name = method.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_") || fn_name.contains("_test") {
            return;
        }

        // Skip NEP standard methods that handle deposits internally
        // NEP-141 (fungible token), NEP-171 (NFT), NEP-145 (storage management)
        let fn_lower = fn_name.to_lowercase();
        if fn_lower == "ft_transfer"
            || fn_lower == "ft_transfer_call"
            || fn_lower == "nft_transfer"
            || fn_lower == "nft_transfer_call"
            || fn_lower == "nft_mint"
            || fn_lower == "nft_approve"
            || fn_lower == "storage_deposit"
            || fn_lower == "storage_withdraw"
            || fn_lower == "storage_unregister"
            || fn_lower.starts_with("ft_on_")
            || fn_lower.starts_with("nft_on_")
        {
            return;
        }

        let line = span_to_line(&method.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "NEAR-010".to_string(),
            name: "missing-deposit-check".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            message: format!(
                "#[payable] method '{}' does not check env::attached_deposit()",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&method.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Add `let deposit = env::attached_deposit(); assert!(deposit > 0);` or validate deposit amount".to_string(),
            chain: Chain::Near,
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
            Chain::Near,
            std::collections::HashMap::new(),
        );
        MissingDepositCheckDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_deposit_check() {
        let source = r#"
            use near_sdk::env;
            impl Contract {
                #[payable]
                pub fn purchase(&mut self, item_id: u64) {
                    self.inventory.remove(&item_id);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing deposit check");
    }

    #[test]
    fn test_no_finding_with_deposit_check() {
        let source = r#"
            use near_sdk::env;
            impl Contract {
                #[payable]
                pub fn purchase(&mut self, item_id: u64) {
                    let deposit = env::attached_deposit();
                    assert!(deposit >= self.prices.get(&item_id).unwrap());
                    self.inventory.remove(&item_id);
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with deposit check");
    }
}
