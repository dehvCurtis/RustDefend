use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;

pub struct UnhandledPromiseDetector;

impl Detector for UnhandledPromiseDetector {
    fn id(&self) -> &'static str {
        "NEAR-004"
    }
    fn name(&self) -> &'static str {
        "callback-unwrap-usage"
    }
    fn description(&self) -> &'static str {
        "Detects #[callback_unwrap] usage (should use #[callback_result] with Result)"
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
        let mut findings = Vec::new();

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

        // Skip SDK infrastructure / macro definition files
        // These define the callback_unwrap attribute itself, not use it
        let path_str = ctx.file_path.to_string_lossy();
        if path_str.contains("/near-sdk-macros/")
            || path_str.contains("/near-sdk/src/")
            || path_str.contains("proc-macro")
            || path_str.contains("derive")
        {
            return findings;
        }

        // Search source for #[callback_unwrap] attribute
        for (line_idx, line) in ctx.source.lines().enumerate() {
            let trimmed = line.trim();

            // Skip comments and doc comments
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*") {
                continue;
            }

            // Skip string literals and macro definitions
            if trimmed.contains("\"callback_unwrap\"") || trimmed.contains("callback_unwrap\"") {
                continue;
            }

            if trimmed.contains("callback_unwrap") && !trimmed.contains("callback_result") {
                let line_num = line_idx + 1;
                findings.push(Finding {
                    detector_id: "NEAR-004".to_string(),
                    name: "callback-unwrap-usage".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: "#[callback_unwrap] will panic on failed promise - use #[callback_result] instead".to_string(),
                    file: ctx.file_path.clone(),
                    line: line_num,
                    column: 1,
                    snippet: trimmed.to_string(),
                    recommendation: "Replace #[callback_unwrap] with #[callback_result] and handle the Result<T, PromiseError> type".to_string(),
                    chain: Chain::Near,
                });
            }
        }

        findings
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
        UnhandledPromiseDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_callback_unwrap() {
        let source = r#"
            use near_sdk::env;
            #[callback_unwrap]
            fn on_transfer_complete(&mut self, amount: U128) {
                self.transferred += amount.0;
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect callback_unwrap");
    }

    #[test]
    fn test_no_finding_callback_result() {
        let source = r#"
            use near_sdk::env;
            #[callback_result]
            fn on_transfer_complete(&mut self, result: Result<U128, PromiseError>) {
                match result {
                    Ok(amount) => self.transferred += amount.0,
                    Err(_) => self.failed += 1,
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag callback_result");
    }
}
