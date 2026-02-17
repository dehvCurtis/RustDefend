use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;

pub struct ReentrancyDetector;

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "INK-001"
    }
    fn name(&self) -> &'static str {
        "ink-reentrancy"
    }
    fn description(&self) -> &'static str {
        "Detects set_allow_reentry(true) which enables reentrancy"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_idx, line) in ctx.source.lines().enumerate() {
            if line.contains("set_allow_reentry") && line.contains("true") {
                let line_num = line_idx + 1;
                findings.push(Finding {
                    detector_id: "INK-001".to_string(),
                    name: "ink-reentrancy".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    message: "set_allow_reentry(true) enables reentrancy attacks".to_string(),
                    file: ctx.file_path.clone(),
                    line: line_num,
                    column: 1,
                    snippet: line.trim().to_string(),
                    recommendation: "Remove set_allow_reentry(true) unless absolutely necessary. The default (false) prevents reentrancy. If needed, implement a reentrancy guard".to_string(),
                    chain: Chain::Ink,
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
            Chain::Ink,
        );
        ReentrancyDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_allow_reentry() {
        let source = r#"
            fn call_other(&mut self) {
                self.env().set_allow_reentry(true);
                let result = other_contract.call();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect set_allow_reentry(true)"
        );
    }

    #[test]
    fn test_no_finding_reentry_false() {
        let source = r#"
            fn call_other(&mut self) {
                self.env().set_allow_reentry(false);
                let result = other_contract.call();
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag set_allow_reentry(false)"
        );
    }
}
