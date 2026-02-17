use std::collections::HashMap;

use quote::ToTokens;
use syn::visit::Visit;
use syn::{ExprCall, ExprMethodCall, ExprPath, ItemFn};

/// What kind of security check to look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    SignerCheck,
    OwnerCheck,
    InputValidation,
}

/// Information about a function extracted from the AST.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Names of functions called directly from this function's body.
    pub calls: Vec<String>,
    /// Whether the function body contains a signer check (is_signer / has_signer).
    pub has_signer_check: bool,
    /// Whether the function body contains an owner check (.owner / program_id check).
    pub has_owner_check: bool,
    /// Whether the function body contains input validation (assert!/require!/ensure!).
    pub has_input_validation: bool,
}

/// A call graph mapping function names to their info.
pub type CallGraph = HashMap<String, FunctionInfo>;

/// Build a call graph from a parsed Rust file.
/// Only tracks top-level `fn` items (not impl methods, for now).
pub fn build_call_graph(ast: &syn::File) -> CallGraph {
    let mut graph = CallGraph::new();

    for item in &ast.items {
        if let syn::Item::Fn(func) = item {
            let info = analyze_function(func);
            graph.insert(func.sig.ident.to_string(), info);
        }
    }

    graph
}

/// Check if any caller of `target_fn` (transitively) already has the given check.
/// Returns true if a caller in the same file performs the check, meaning
/// the target function doesn't need to re-check.
pub fn caller_has_check(graph: &CallGraph, target_fn: &str, check: CheckKind) -> bool {
    // Find all functions that call target_fn (directly or transitively)
    let mut visited = Vec::new();
    has_check_in_callers(graph, target_fn, check, &mut visited, 0)
}

/// Maximum traversal depth to prevent cycles.
const MAX_DEPTH: usize = 5;

fn has_check_in_callers(
    graph: &CallGraph,
    target_fn: &str,
    check: CheckKind,
    visited: &mut Vec<String>,
    depth: usize,
) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }

    // Find all functions that call target_fn
    for (fn_name, info) in graph {
        if fn_name == target_fn {
            continue;
        }
        if visited.contains(fn_name) {
            continue;
        }
        if !info.calls.iter().any(|c| c == target_fn) {
            continue;
        }

        // This function calls target_fn — check if it has the relevant check
        let has_it = match check {
            CheckKind::SignerCheck => info.has_signer_check,
            CheckKind::OwnerCheck => info.has_owner_check,
            CheckKind::InputValidation => info.has_input_validation,
        };

        if has_it {
            return true;
        }

        // Recurse: does anyone calling this caller have the check?
        visited.push(fn_name.clone());
        if has_check_in_callers(graph, fn_name, check, visited, depth + 1) {
            return true;
        }
    }

    false
}

/// Analyze a single function to extract call graph info.
fn analyze_function(func: &ItemFn) -> FunctionInfo {
    let body_src = func.block.to_token_stream().to_string();

    let has_signer_check = body_src.contains("is_signer") || body_src.contains("has_signer");

    let has_owner_check =
        body_src.contains("owner") && (body_src.contains("program_id") || body_src.contains("key"));

    let has_input_validation = body_src.contains("assert!")
        || body_src.contains("assert_eq!")
        || body_src.contains("assert_ne!")
        || body_src.contains("require!")
        || body_src.contains("ensure!");

    let mut collector = CallCollector { calls: Vec::new() };
    collector.visit_item_fn(func);

    FunctionInfo {
        calls: collector.calls,
        has_signer_check,
        has_owner_check,
        has_input_validation,
    }
}

/// Visitor that collects function call names from expressions.
struct CallCollector {
    calls: Vec<String>,
}

impl<'ast> Visit<'ast> for CallCollector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        // Extract the function name from the call expression
        if let syn::Expr::Path(ExprPath { path, .. }) = node.func.as_ref() {
            if let Some(ident) = path.get_ident() {
                let name = ident.to_string();
                if !self.calls.contains(&name) {
                    self.calls.push(name);
                }
            } else if let Some(segment) = path.segments.last() {
                // Handle paths like module::function
                let name = segment.ident.to_string();
                if !self.calls.contains(&name) {
                    self.calls.push(name);
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if !self.calls.contains(&name) {
            self.calls.push(name);
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_build(source: &str) -> CallGraph {
        let ast = syn::parse_file(source).unwrap();
        build_call_graph(&ast)
    }

    #[test]
    fn test_caller_checks_signer_propagates() {
        let source = r#"
            fn process_instruction(account: &AccountInfo) {
                if !account.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                transfer(account);
            }

            fn transfer(account: &AccountInfo) {
                // does something without checking signer
                let data = account.try_borrow_mut_data().unwrap();
            }
        "#;
        let graph = parse_and_build(source);

        // transfer is called by process_instruction which checks signer
        assert!(caller_has_check(&graph, "transfer", CheckKind::SignerCheck));
    }

    #[test]
    fn test_no_caller_means_no_propagation() {
        let source = r#"
            fn transfer(account: &AccountInfo) {
                let data = account.try_borrow_mut_data().unwrap();
            }
        "#;
        let graph = parse_and_build(source);

        // No caller in the file
        assert!(!caller_has_check(
            &graph,
            "transfer",
            CheckKind::SignerCheck
        ));
    }

    #[test]
    fn test_cycle_no_infinite_loop() {
        let source = r#"
            fn a() {
                b();
            }

            fn b() {
                a();
            }
        "#;
        let graph = parse_and_build(source);

        // Should not infinite loop
        assert!(!caller_has_check(&graph, "a", CheckKind::SignerCheck));
        assert!(!caller_has_check(&graph, "b", CheckKind::SignerCheck));
    }

    #[test]
    fn test_transitive_propagation() {
        let source = r#"
            fn entry(account: &AccountInfo) {
                if !account.is_signer {
                    panic!("no signer");
                }
                middle(account);
            }

            fn middle(account: &AccountInfo) {
                leaf(account);
            }

            fn leaf(account: &AccountInfo) {
                let data = account.try_borrow_mut_data().unwrap();
            }
        "#;
        let graph = parse_and_build(source);

        // entry -> middle -> leaf; entry checks signer
        assert!(caller_has_check(&graph, "middle", CheckKind::SignerCheck));
        assert!(caller_has_check(&graph, "leaf", CheckKind::SignerCheck));
    }

    #[test]
    fn test_owner_check_propagation() {
        let source = r#"
            fn process(account: &AccountInfo, program_id: &Pubkey) {
                if account.owner != program_id {
                    return Err(ProgramError::IncorrectProgramId);
                }
                helper(account);
            }

            fn helper(account: &AccountInfo) {
                let data = account.try_borrow_data().unwrap();
            }
        "#;
        let graph = parse_and_build(source);

        assert!(caller_has_check(&graph, "helper", CheckKind::OwnerCheck));
    }
}
