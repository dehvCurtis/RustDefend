use proc_macro2::Span;
use syn::visit::Visit;
use syn::{Attribute, ExprMethodCall, ItemFn, Stmt};

/// Convert a proc_macro2 Span to a 1-based line number.
pub fn span_to_line(span: &Span) -> usize {
    span.start().line
}

/// Convert a proc_macro2 Span to a 1-based column number.
pub fn span_to_column(span: &Span) -> usize {
    span.start().column + 1
}

/// Get the source snippet at a given 1-based line.
pub fn snippet_at_line(source: &str, line: usize) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Check if a function has a specific attribute (e.g., #[private], #[ink(message)]).
pub fn has_attribute(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        if let Some(ident) = attr.path().get_ident() {
            return ident == name;
        }
        // Check for nested like #[ink(message)]
        let path_str = attr
            .path()
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        path_str == name
    })
}

/// Check if attributes contain a specific nested attribute like #[ink(message)].
pub fn has_nested_attribute(attrs: &[Attribute], outer: &str, inner: &str) -> bool {
    attrs.iter().any(|attr| {
        if let Some(ident) = attr.path().get_ident() {
            if ident == outer {
                // Parse the tokens inside the attribute
                let tokens = attr.meta.to_token_stream().to_string();
                return tokens.contains(inner);
            }
        }
        false
    })
}

use quote::ToTokens;

/// Check if an attribute contains a specific key-value like #[account(close = recipient)].
pub fn has_attribute_with_value(attrs: &[Attribute], outer: &str, key: &str) -> bool {
    attrs.iter().any(|attr| {
        if let Some(ident) = attr.path().get_ident() {
            if ident == outer {
                let tokens = attr.meta.to_token_stream().to_string();
                return tokens.contains(key);
            }
        }
        false
    })
}

/// Collect all method calls in an expression tree.
pub struct MethodCallCollector {
    pub calls: Vec<ExprMethodCall>,
}

impl<'ast> Visit<'ast> for MethodCallCollector {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        self.calls.push(node.clone());
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Collect all function items in a file.
pub struct FunctionCollector {
    pub functions: Vec<ItemFn>,
}

impl<'ast> Visit<'ast> for FunctionCollector {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.functions.push(node.clone());
        syn::visit::visit_item_fn(self, node);
    }
}

/// Check if a source line contains any of the given patterns.
pub fn source_contains_any(source: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| source.contains(p))
}

/// Find all method calls with a specific name in a block of statements.
pub fn find_method_calls_in_stmts<'a>(stmts: &'a [Stmt], method_name: &str) -> Vec<&'a ExprMethodCall> {
    struct Finder<'b> {
        name: &'b str,
        found: Vec<*const ExprMethodCall>,
    }
    impl<'ast, 'b> Visit<'ast> for Finder<'b> {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            if node.method == self.name {
                self.found.push(node as *const ExprMethodCall);
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    let mut finder = Finder {
        name: method_name,
        found: vec![],
    };
    for stmt in stmts {
        finder.visit_stmt(stmt);
    }
    // Safety: pointers are valid for lifetime 'a since stmts outlives finder
    finder
        .found
        .into_iter()
        .map(|p| unsafe { &*p })
        .collect()
}

/// Check if source text contains a check for a specific field/method before a given line.
pub fn has_check_before_line(source: &str, check_pattern: &str, before_line: usize) -> bool {
    source
        .lines()
        .take(before_line.saturating_sub(1))
        .any(|line| line.contains(check_pattern))
}

/// Check if a function body source contains a specific pattern.
pub fn fn_body_contains(func: &ItemFn, pattern: &str) -> bool {
    let body = func.block.to_token_stream().to_string();
    body.contains(pattern)
}

/// Extract the string representation of a function's body.
pub fn fn_body_source(func: &ItemFn) -> String {
    func.block.to_token_stream().to_string()
}
