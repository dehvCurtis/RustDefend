use std::collections::HashMap;

use syn::visit::Visit;
use syn::{ItemFn, ItemUse, Local, Pat, Type};

/// AST-level type inference map.
///
/// This is a proof-of-concept for type-aware analysis. It extracts type annotations
/// from variable declarations and `use` statements to build a mapping from variable
/// names to their inferred types.
///
/// This is NOT equivalent to rustc MIR — it only captures explicit type annotations
/// visible in the AST. Documented as approximate.
#[derive(Debug, Clone, Default)]
pub struct TypeMap {
    /// Maps variable names to their inferred type strings.
    pub vars: HashMap<String, String>,
    /// Imported type names from `use` statements.
    pub imported_types: Vec<String>,
}

/// Known safe types for arithmetic operations.
/// These types have built-in overflow protection.
const SAFE_ARITHMETIC_TYPES: &[&str] = &[
    "Uint128",
    "Uint256",
    "Uint512",
    "Uint64",
    "U128",
    "U256",
    "U512",
    "Decimal",
    "Decimal256",
    "SignedDecimal",
    "SignedDecimal256",
    "Int128",
    "Int256",
    "Int512",
];

impl TypeMap {
    /// Build a type map from a parsed Rust file.
    pub fn from_ast(ast: &syn::File) -> Self {
        let mut map = TypeMap::default();
        let mut visitor = TypeCollector { map: &mut map };
        visitor.visit_file(ast);
        map
    }

    /// Check if a variable has an arithmetic-safe type.
    pub fn is_safe_arithmetic_type(&self, var_name: &str) -> bool {
        if let Some(type_str) = self.vars.get(var_name) {
            return SAFE_ARITHMETIC_TYPES
                .iter()
                .any(|safe| type_str.contains(safe));
        }
        false
    }

    /// Check if any safe arithmetic type is imported in the file.
    pub fn has_safe_type_imports(&self) -> bool {
        self.imported_types
            .iter()
            .any(|t| SAFE_ARITHMETIC_TYPES.iter().any(|safe| t.contains(safe)))
    }
}

struct TypeCollector<'a> {
    map: &'a mut TypeMap,
}

impl<'ast, 'a> Visit<'ast> for TypeCollector<'a> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        // Extract imported type names
        let use_str = quote::ToTokens::to_token_stream(node).to_string();
        // Simple extraction: look for known type names in use statements
        for safe_type in SAFE_ARITHMETIC_TYPES {
            if use_str.contains(safe_type) {
                self.map.imported_types.push(safe_type.to_string());
            }
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // Visit function body for local variable declarations
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_local(&mut self, node: &'ast Local) {
        // Extract variable name and type from `let x: Type = ...`
        if let Pat::Type(pat_type) = &node.pat {
            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                let var_name = pat_ident.ident.to_string();
                let type_str = type_to_string(&pat_type.ty);
                self.map.vars.insert(var_name, type_str);
            }
        }
        syn::visit::visit_local(self, node);
    }
}

fn type_to_string(ty: &Type) -> String {
    quote::ToTokens::to_token_stream(ty).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_type_map(source: &str) -> TypeMap {
        let ast = syn::parse_file(source).unwrap();
        TypeMap::from_ast(&ast)
    }

    #[test]
    fn test_extracts_typed_variables() {
        let source = r#"
            fn process() {
                let amount: Uint128 = Uint128::new(100);
                let count: u64 = 0;
            }
        "#;
        let map = build_type_map(source);
        assert_eq!(map.vars.get("amount").map(|s| s.as_str()), Some("Uint128"));
        assert_eq!(map.vars.get("count").map(|s| s.as_str()), Some("u64"));
    }

    #[test]
    fn test_safe_arithmetic_type_detection() {
        let source = r#"
            fn process() {
                let amount: Uint128 = Uint128::new(100);
                let raw: u64 = 0;
            }
        "#;
        let map = build_type_map(source);
        assert!(map.is_safe_arithmetic_type("amount"));
        assert!(!map.is_safe_arithmetic_type("raw"));
    }

    #[test]
    fn test_detects_safe_type_imports() {
        let source = r#"
            use cosmwasm_std::Uint128;
            fn process() {}
        "#;
        let map = build_type_map(source);
        assert!(map.has_safe_type_imports());
    }

    #[test]
    fn test_no_safe_imports() {
        let source = r#"
            use solana_program::account_info::AccountInfo;
            fn process() {}
        "#;
        let map = build_type_map(source);
        assert!(!map.has_safe_type_imports());
    }
}
