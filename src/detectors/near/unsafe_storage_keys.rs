use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct UnsafeStorageKeysDetector;

impl Detector for UnsafeStorageKeysDetector {
    fn id(&self) -> &'static str {
        "NEAR-009"
    }
    fn name(&self) -> &'static str {
        "unsafe-storage-keys"
    }
    fn description(&self) -> &'static str {
        "Detects storage key construction from user input (collision risk)"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
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
        let mut visitor = StorageKeyVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct StorageKeyVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for StorageKeyVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();
        if fn_name.starts_with("test_") || has_attribute(&func.attrs, "test") {
            return;
        }

        let body_src = fn_body_source(func);

        // Look for storage write with format! or string concatenation in key
        let has_storage_write =
            body_src.contains("storage_write") || body_src.contains("storage_read");

        let has_dynamic_key =
            (body_src.contains("format !") || body_src.contains("format!")) && has_storage_write;

        if !has_dynamic_key {
            return;
        }

        // Check if the format string is used as a storage key
        // Skip if using sha256 or borsh serialization for keys
        if body_src.contains("sha256")
            || body_src.contains("keccak")
            || body_src.contains("BorshSerialize")
            || body_src.contains("borsh")
        {
            return;
        }

        let line = span_to_line(&func.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "NEAR-009".to_string(),
            name: "unsafe-storage-keys".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            message: format!(
                "Function '{}' constructs storage keys from user input via format!()",
                fn_name
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&func.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Use BorshSerialize or enum-based namespacing for storage keys to prevent collisions".to_string(),
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
        UnsafeStorageKeysDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_format_storage_key() {
        let source = r#"
            use near_sdk::env;
            fn store_user_data(user_id: &str, data: &[u8]) {
                let key = format!("user_{}", user_id);
                env::storage_write(key.as_bytes(), data);
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect format! in storage key");
    }

    #[test]
    fn test_no_finding_fixed_prefix() {
        let source = r#"
            use near_sdk::env;
            fn store_data(data: &[u8]) {
                env::storage_write(b"config", data);
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag fixed storage keys");
    }
}
