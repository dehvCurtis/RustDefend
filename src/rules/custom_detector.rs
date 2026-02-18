use quote::ToTokens;
use syn::visit::Visit;
use syn::ItemFn;

use crate::detectors::Detector;
use crate::rules::engine;
use crate::rules::parser::CustomRule;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

/// Wraps a `CustomRule` as a `Detector` implementation.
pub struct CustomDetector {
    rule: CustomRule,
    // Leaked strings for 'static lifetime requirement of the Detector trait.
    // Acceptable for a CLI tool that runs once per invocation.
    id: &'static str,
    name: &'static str,
    description: &'static str,
}

impl CustomDetector {
    pub fn new(rule: CustomRule) -> Self {
        let id: &'static str = Box::leak(rule.id.clone().into_boxed_str());
        let name: &'static str = Box::leak(rule.name.clone().into_boxed_str());
        let description: &'static str = Box::leak(rule.message.clone().into_boxed_str());
        Self {
            rule,
            id,
            name,
            description,
        }
    }
}

impl Detector for CustomDetector {
    fn id(&self) -> &'static str {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn severity(&self) -> Severity {
        Severity::from_str_loose(&self.rule.severity).unwrap_or(Severity::Medium)
    }

    fn confidence(&self) -> Confidence {
        Confidence::from_str_loose(&self.rule.confidence).unwrap_or(Confidence::Medium)
    }

    fn chain(&self) -> Chain {
        self.rule
            .chain
            .as_deref()
            .and_then(Chain::from_str_loose)
            .unwrap_or(Chain::Solana) // default chain for custom rules
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        // If chain filter is set, only run on matching files
        if let Some(ref chain_str) = self.rule.chain {
            if let Some(chain) = Chain::from_str_loose(chain_str) {
                if ctx.chain != chain {
                    return Vec::new();
                }
            }
        }

        let mut findings = Vec::new();
        let mut visitor = CustomRuleVisitor {
            findings: &mut findings,
            ctx,
            rule: &self.rule,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct CustomRuleVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
    rule: &'a CustomRule,
}

impl<'ast, 'a> Visit<'ast> for CustomRuleVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        let fn_name = func.sig.ident.to_string();
        let fn_src = func.to_token_stream().to_string();

        // Skip test functions if configured
        if self.rule.exclude_tests && engine::is_test_function(&fn_name, &fn_src) {
            return;
        }

        let body_src = fn_body_source(func);
        let fn_line = span_to_line(&func.sig.ident.span());

        if let Some(match_line) =
            engine::matches_rule(&self.ctx.source, &body_src, fn_line, self.rule)
        {
            self.findings.push(Finding {
                detector_id: self.rule.id.clone(),
                name: self.rule.name.clone(),
                severity: Severity::from_str_loose(&self.rule.severity).unwrap_or(Severity::Medium),
                confidence: Confidence::from_str_loose(&self.rule.confidence)
                    .unwrap_or(Confidence::Medium),
                message: format!("{} (in function '{}')", self.rule.message, func.sig.ident),
                file: self.ctx.file_path.clone(),
                line: match_line,
                column: 1,
                snippet: snippet_at_line(&self.ctx.source, match_line),
                recommendation: self.rule.recommendation.clone(),
                chain: self.ctx.chain,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule() -> CustomRule {
        CustomRule {
            id: "CUSTOM-001".to_string(),
            name: "no-unsafe".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            chain: None,
            pattern: "unsafe {".to_string(),
            message: "Unsafe block detected".to_string(),
            recommendation: "Remove unsafe blocks".to_string(),
            exclude_tests: true,
        }
    }

    fn run_custom_detector(source: &str, rule: CustomRule) -> Vec<Finding> {
        let ast = syn::parse_file(source).unwrap();
        let ctx = ScanContext::new(
            std::path::PathBuf::from("test.rs"),
            source.to_string(),
            ast,
            Chain::Solana,
            std::collections::HashMap::new(),
        );
        let detector = CustomDetector::new(rule);
        detector.detect(&ctx)
    }

    #[test]
    fn test_custom_detector_finds_pattern() {
        let source = r#"
            fn process() {
                unsafe { do_thing(); }
            }
        "#;
        let findings = run_custom_detector(source, make_rule());
        assert!(!findings.is_empty(), "Should detect unsafe block");
        assert_eq!(findings[0].detector_id, "CUSTOM-001");
    }

    #[test]
    fn test_custom_detector_skips_test() {
        let source = r#"
            #[test]
            fn test_process() {
                unsafe { do_thing(); }
            }
        "#;
        let findings = run_custom_detector(source, make_rule());
        assert!(findings.is_empty(), "Should skip test functions");
    }

    #[test]
    fn test_custom_detector_no_match() {
        let source = r#"
            fn process() {
                safe_thing();
            }
        "#;
        let findings = run_custom_detector(source, make_rule());
        assert!(findings.is_empty(), "Should not match without pattern");
    }
}
