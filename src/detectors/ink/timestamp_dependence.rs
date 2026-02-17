use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;

pub struct TimestampDependenceDetector;

impl Detector for TimestampDependenceDetector {
    fn id(&self) -> &'static str {
        "INK-004"
    }
    fn name(&self) -> &'static str {
        "ink-timestamp-dependence"
    }
    fn description(&self) -> &'static str {
        "Detects block_timestamp() usage in decision logic"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_idx, line) in ctx.source.lines().enumerate() {
            if line.contains("block_timestamp") {
                // Check if used in comparison or arithmetic
                let in_decision = line.contains('<')
                    || line.contains('>')
                    || line.contains("==")
                    || line.contains("!=")
                    || line.contains("if")
                    || line.contains("match")
                    || line.contains('+')
                    || line.contains('-');

                if in_decision {
                    let line_num = line_idx + 1;
                    findings.push(Finding {
                        detector_id: "INK-004".to_string(),
                        name: "ink-timestamp-dependence".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        message: "block_timestamp() used in decision logic - can be manipulated by validators".to_string(),
                        file: ctx.file_path.clone(),
                        line: line_num,
                        column: 1,
                        snippet: line.trim().to_string(),
                        recommendation: "Block timestamps can be slightly manipulated by validators. Use block_number() for ordering, or add tolerance margins for time-based logic".to_string(),
                        chain: Chain::Ink,
                    });
                }
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
            Chain::Ink,
        );
        TimestampDependenceDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_timestamp_comparison() {
        let source = r#"
            fn is_expired(&self) -> bool {
                self.env().block_timestamp() > self.deadline
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect timestamp in comparison"
        );
    }

    #[test]
    fn test_no_finding_timestamp_logging() {
        let source = r#"
            fn get_timestamp(&self) -> u64 {
                self.env().block_timestamp()
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag simple timestamp read");
    }
}
