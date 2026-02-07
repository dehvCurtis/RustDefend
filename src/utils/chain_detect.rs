use std::path::Path;

use crate::scanner::finding::Chain;

/// Detect which blockchain chains are targeted by examining Cargo.toml dependencies.
pub fn detect_chains(path: &Path) -> Vec<Chain> {
    let cargo_toml_path = if path.is_file() {
        // Walk up to find Cargo.toml
        path.ancestors()
            .find(|p| p.join("Cargo.toml").exists())
            .map(|p| p.join("Cargo.toml"))
    } else {
        let direct = path.join("Cargo.toml");
        if direct.exists() {
            Some(direct)
        } else {
            // Try parent directories
            path.ancestors()
                .find(|p| p.join("Cargo.toml").exists())
                .map(|p| p.join("Cargo.toml"))
        }
    };

    let cargo_toml_path = match cargo_toml_path {
        Some(p) if p.exists() => p,
        _ => return vec![],
    };

    let content = match std::fs::read_to_string(&cargo_toml_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let parsed: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut chains = Vec::new();

    // Check dependencies and dev-dependencies
    let dep_sections = ["dependencies", "dev-dependencies"];
    for section in &dep_sections {
        if let Some(deps) = parsed.get(section).and_then(|v| v.as_table()) {
            for key in deps.keys() {
                match key.as_str() {
                    "anchor-lang" | "anchor-spl" | "solana-program" | "solana-sdk" => {
                        if !chains.contains(&Chain::Solana) {
                            chains.push(Chain::Solana);
                        }
                    }
                    "cosmwasm-std" | "cosmwasm-storage" | "cw-storage-plus" | "sylvia" => {
                        if !chains.contains(&Chain::CosmWasm) {
                            chains.push(Chain::CosmWasm);
                        }
                    }
                    "near-sdk" | "near-contract-standards" => {
                        if !chains.contains(&Chain::Near) {
                            chains.push(Chain::Near);
                        }
                    }
                    "ink" | "ink_lang" | "ink_storage" | "ink_env" => {
                        if !chains.contains(&Chain::Ink) {
                            chains.push(Chain::Ink);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    chains
}
