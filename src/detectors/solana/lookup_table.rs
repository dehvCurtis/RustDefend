use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct LookupTableDetector;

impl Detector for LookupTableDetector {
    fn id(&self) -> &'static str {
        "SOL-015"
    }
    fn name(&self) -> &'static str {
        "lookup-table-manipulation"
    }
    fn description(&self) -> &'static str {
        "Detects AddressLookupTableAccount usage without authority or freeze verification"
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
        // Quick check: skip files that don't mention lookup tables at all
        if !ctx.source.contains("AddressLookupTableAccount")
            && !ctx.source.contains("LookupTableAccount")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut visitor = LookupTableVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

const TRIGGER_PATTERNS: &[&str] = &["AddressLookupTableAccount", "LookupTableAccount"];

const SAFE_PATTERNS: &[&str] = &[
    "meta.authority",
    "meta . authority",
    "freeze_authority",
    "is_frozen",
    "lookup_table.meta",
    "lookup_table . meta",
];

const TRANSACTION_PATTERNS: &[&str] = &[
    "VersionedTransaction",
    "MessageV0",
    "v0::Message",
    "address_lookup_table_accounts",
    "compile_v0",
    "new_v0",
];

struct LookupTableVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for LookupTableVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();

        // Skip test functions
        if fn_name.starts_with("test_")
            || fn_name.ends_with("_test")
            || has_attribute(&func.attrs, "test")
        {
            return;
        }

        let fn_src = func.to_token_stream().to_string();
        let body_src = fn_body_source(func);

        // Check for trigger patterns
        let has_trigger = TRIGGER_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        if !has_trigger {
            return;
        }

        // Check for safe authority/freeze patterns
        let has_safe = SAFE_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        if has_safe {
            return;
        }

        // Check if the lookup table is used in a transaction context
        let in_tx_context = TRANSACTION_PATTERNS
            .iter()
            .any(|p| body_src.contains(p) || fn_src.contains(p));

        if !in_tx_context {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "SOL-015".to_string(),
            name: "lookup-table-manipulation".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' uses AddressLookupTableAccount in transaction context without verifying authority or freeze status",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Verify lookup table authority and freeze status before using in transactions to prevent manipulation attacks".to_string(),
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
        LookupTableDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_lookup_table_without_authority_check() {
        let source = r#"
            fn build_versioned_tx(lookup_table: AddressLookupTableAccount) {
                let accounts = vec![lookup_table];
                let msg = MessageV0::try_compile(
                    &payer.pubkey(),
                    &instructions,
                    &accounts,
                    recent_blockhash,
                )?;
                let tx = VersionedTransaction::try_new(msg, &[&payer])?;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect lookup table usage without authority check"
        );
        assert_eq!(findings[0].detector_id, "SOL-015");
    }

    #[test]
    fn test_no_finding_with_authority_check() {
        let source = r#"
            fn build_versioned_tx(lookup_table: AddressLookupTableAccount) {
                if lookup_table.meta.authority != Some(expected_authority) {
                    return Err(Error::InvalidAuthority);
                }
                let accounts = vec![lookup_table];
                let msg = MessageV0::try_compile(
                    &payer.pubkey(),
                    &instructions,
                    &accounts,
                    recent_blockhash,
                )?;
                let tx = VersionedTransaction::try_new(msg, &[&payer])?;
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag when authority check is present"
        );
    }
}
