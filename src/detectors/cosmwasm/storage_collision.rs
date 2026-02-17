use quote::ToTokens;
use std::collections::HashMap;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprLit, Lit};

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct StorageCollisionDetector;

impl Detector for StorageCollisionDetector {
    fn id(&self) -> &'static str {
        "CW-004"
    }
    fn name(&self) -> &'static str {
        "storage-collision"
    }
    fn description(&self) -> &'static str {
        "Detects duplicate storage prefixes in Map::new() / Item::new()"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::CosmWasm
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all storage constructor calls with string prefixes
        let mut prefix_locations: HashMap<String, Vec<usize>> = HashMap::new();
        let mut visitor = StorageVisitor {
            prefixes: &mut prefix_locations,
        };
        visitor.visit_file(&ctx.ast);

        // Report duplicates
        for (prefix, lines) in &prefix_locations {
            if lines.len() > 1 {
                for &line in &lines[1..] {
                    findings.push(Finding {
                        detector_id: "CW-004".to_string(),
                        name: "storage-collision".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        message: format!(
                            "Duplicate storage prefix '{}' (also used at line {})",
                            prefix, lines[0]
                        ),
                        file: ctx.file_path.clone(),
                        line,
                        column: 1,
                        snippet: snippet_at_line(&ctx.source, line),
                        recommendation:
                            "Each storage item must have a unique prefix to prevent data collisions"
                                .to_string(),
                        chain: Chain::CosmWasm,
                    });
                }
            }
        }

        findings
    }
}

struct StorageVisitor<'a> {
    prefixes: &'a mut HashMap<String, Vec<usize>>,
}

impl<'ast, 'a> Visit<'ast> for StorageVisitor<'a> {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        let func_str = call.func.to_token_stream().to_string();

        // Match Map::new, Item::new, Deque::new etc.
        if (func_str.contains(":: new") || func_str.contains("::new"))
            && (func_str.contains("Map")
                || func_str.contains("Item")
                || func_str.contains("Deque")
                || func_str.contains("SnapshotMap")
                || func_str.contains("SnapshotItem"))
        {
            // Extract the first string argument (prefix)
            if let Some(first_arg) = call.args.first() {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = first_arg
                {
                    let prefix = s.value();
                    let line = span_to_line(&s.span());
                    self.prefixes.entry(prefix).or_default().push(line);
                }
            }
        }

        syn::visit::visit_expr_call(self, call);
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
            Chain::CosmWasm,
            std::collections::HashMap::new(),
        );
        StorageCollisionDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_duplicate_prefix() {
        let source = r#"
            const BALANCES: Map<&Addr, Uint128> = Map::new("balances");
            const ALLOWANCES: Map<&Addr, Uint128> = Map::new("balances");
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect duplicate prefix");
    }

    #[test]
    fn test_no_finding_unique_prefixes() {
        let source = r#"
            const BALANCES: Map<&Addr, Uint128> = Map::new("balances");
            const ALLOWANCES: Map<(&Addr, &Addr), Uint128> = Map::new("allowances");
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag unique prefixes");
    }
}
