
use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;

pub struct CrossContractDetector;

impl Detector for CrossContractDetector {
    fn id(&self) -> &'static str { "INK-006" }
    fn name(&self) -> &'static str { "ink-cross-contract" }
    fn description(&self) -> &'static str {
        "Detects try_invoke() without result check"
    }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn chain(&self) -> Chain { Chain::Ink }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_idx, line) in ctx.source.lines().enumerate() {
            if line.contains("try_invoke") {
                let line_num = line_idx + 1;

                // Check if result is handled
                let is_handled = line.contains('?')
                    || line.contains("match")
                    || line.contains("unwrap")
                    || line.contains("expect")
                    || line.contains("if let")
                    || line.contains("map_err");

                // Check next line for match/if let
                let next_line_handled = ctx.source.lines()
                    .nth(line_idx + 1)
                    .map(|l| l.contains("match") || l.contains("if let") || l.contains('?'))
                    .unwrap_or(false);

                // Check for let _ = pattern
                let is_discarded = line.contains("let _");

                if (!is_handled && !next_line_handled) || is_discarded {
                    findings.push(Finding {
                        detector_id: "INK-006".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        message: "try_invoke() result is not checked".to_string(),
                        file: ctx.file_path.clone(),
                        line: line_num,
                        column: 1,
                        snippet: line.trim().to_string(),
                        recommendation: "Handle the try_invoke() result with `?` operator or match on Ok/Err".to_string(),
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
        CrossContractDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_unchecked_invoke() {
        let source = r#"
            fn call_other(&mut self) {
                let _ = self.other_contract.try_invoke();
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect unchecked try_invoke");
    }

    #[test]
    fn test_no_finding_with_question_mark() {
        let source = r#"
            fn call_other(&mut self) -> Result<(), Error> {
                let result = self.other_contract.try_invoke()?;
                Ok(())
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with ? operator");
    }
}
