use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::scanner::finding::Chain;

/// Maps each crate root directory to its detected chains.
pub type CrateChainCache = HashMap<PathBuf, Vec<Chain>>;

/// Build a mapping from each crate root directory to its detected chains.
///
/// For workspace projects, reads the root Cargo.toml `[workspace] members` list,
/// then resolves each member's Cargo.toml to detect chains individually.
/// For single-crate projects, returns a single entry for the root.
pub fn build_workspace_chain_map(root_path: &Path) -> CrateChainCache {
    let mut cache = CrateChainCache::new();

    let cargo_toml_path = find_cargo_toml(root_path);
    let cargo_toml_path = match cargo_toml_path {
        Some(p) => p,
        None => return cache,
    };

    let content = match std::fs::read_to_string(&cargo_toml_path) {
        Ok(c) => c,
        Err(_) => return cache,
    };

    let parsed: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return cache,
    };

    let workspace_root = cargo_toml_path.parent().unwrap_or(root_path);

    // Check if this is a workspace
    if let Some(workspace) = parsed.get("workspace") {
        if let Some(members) = workspace.get("members").and_then(|v| v.as_array()) {
            for member in members {
                if let Some(member_str) = member.as_str() {
                    // Expand glob patterns
                    let member_paths = expand_member_glob(workspace_root, member_str);
                    for member_path in member_paths {
                        let member_cargo = member_path.join("Cargo.toml");
                        if member_cargo.exists() {
                            let chains = detect_chains_from_manifest(&member_cargo);
                            let canonical = normalize_path(&member_path);
                            cache.insert(canonical, chains);
                        }
                    }
                }
            }
        }
    }

    // Also detect chains for the root itself (virtual workspace may have no deps,
    // but a real crate at root might)
    if parsed.get("package").is_some() {
        let chains = detect_chains_from_manifest(&cargo_toml_path);
        let canonical = normalize_path(workspace_root);
        cache.insert(canonical, chains);
    }

    // If no workspace members found, treat as single crate
    if cache.is_empty() {
        let chains = detect_chains_from_manifest(&cargo_toml_path);
        let canonical = normalize_path(workspace_root);
        cache.insert(canonical, chains);
    }

    cache
}

/// Find the crate root directory for a given .rs file by walking up to find
/// the nearest Cargo.toml.
pub fn find_crate_root(file_path: &Path) -> Option<PathBuf> {
    let mut current = if file_path.is_file() {
        file_path.parent()?
    } else {
        file_path
    };

    loop {
        if current.join("Cargo.toml").exists() {
            return Some(normalize_path(current));
        }
        current = current.parent()?;
    }
}

/// Detect chains from a specific Cargo.toml manifest file.
pub fn detect_chains_from_manifest(cargo_toml_path: &Path) -> Vec<Chain> {
    let content = match std::fs::read_to_string(cargo_toml_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let parsed: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut chains = Vec::new();

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

/// Find the closest Cargo.toml from a given path.
fn find_cargo_toml(path: &Path) -> Option<PathBuf> {
    if path.is_file() {
        path.ancestors()
            .find(|p| p.join("Cargo.toml").exists())
            .map(|p| p.join("Cargo.toml"))
    } else {
        let direct = path.join("Cargo.toml");
        if direct.exists() {
            Some(direct)
        } else {
            path.ancestors()
                .find(|p| p.join("Cargo.toml").exists())
                .map(|p| p.join("Cargo.toml"))
        }
    }
}

/// Expand workspace member glob patterns (e.g., "programs/*") into actual directories.
fn expand_member_glob(workspace_root: &Path, pattern: &str) -> Vec<PathBuf> {
    if pattern.contains('*') || pattern.contains('?') {
        // Simple glob expansion: handle "dir/*" pattern
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 && parts[1].is_empty() {
            // Pattern like "programs/*"
            let base = workspace_root.join(parts[0].trim_end_matches('/'));
            if base.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&base) {
                    return entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        .map(|e| e.path())
                        .collect();
                }
            }
        }
        // For more complex patterns, fall back to checking if Cargo.toml exists
        vec![]
    } else {
        let member_path = workspace_root.join(pattern);
        if member_path.exists() {
            vec![member_path]
        } else {
            vec![]
        }
    }
}

/// Normalize a path for consistent HashMap keys.
fn normalize_path(path: &Path) -> PathBuf {
    // Use canonicalize if possible, otherwise use the path as-is
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Look up chains for a file from the workspace chain map, with fallback.
pub fn chains_for_file(
    chain_map: &CrateChainCache,
    file_path: &Path,
    fallback: &[Chain],
) -> Vec<Chain> {
    if let Some(crate_root) = find_crate_root(file_path) {
        if let Some(chains) = chain_map.get(&crate_root) {
            if !chains.is_empty() {
                return chains.clone();
            }
        }
    }
    fallback.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_workspace_with_two_members() {
        let tmp = std::env::temp_dir().join("rustdefend_test_ws_two");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // Create workspace root
        fs::write(
            tmp.join("Cargo.toml"),
            r#"
[workspace]
members = ["solana-crate", "cosmwasm-crate"]
"#,
        )
        .unwrap();

        // Solana member
        let sol_dir = tmp.join("solana-crate");
        fs::create_dir_all(sol_dir.join("src")).unwrap();
        fs::write(
            sol_dir.join("Cargo.toml"),
            r#"
[package]
name = "solana-crate"
version = "0.1.0"

[dependencies]
anchor-lang = "0.28"
"#,
        )
        .unwrap();
        fs::write(sol_dir.join("src/lib.rs"), "// solana code").unwrap();

        // CosmWasm member
        let cw_dir = tmp.join("cosmwasm-crate");
        fs::create_dir_all(cw_dir.join("src")).unwrap();
        fs::write(
            cw_dir.join("Cargo.toml"),
            r#"
[package]
name = "cosmwasm-crate"
version = "0.1.0"

[dependencies]
cosmwasm-std = "1.5"
"#,
        )
        .unwrap();
        fs::write(cw_dir.join("src/lib.rs"), "// cosmwasm code").unwrap();

        let chain_map = build_workspace_chain_map(&tmp);

        // Verify solana-crate maps to Solana
        let sol_chains = chains_for_file(&chain_map, &sol_dir.join("src/lib.rs"), &[]);
        assert_eq!(sol_chains, vec![Chain::Solana]);

        // Verify cosmwasm-crate maps to CosmWasm
        let cw_chains = chains_for_file(&chain_map, &cw_dir.join("src/lib.rs"), &[]);
        assert_eq!(cw_chains, vec![Chain::CosmWasm]);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_single_crate_fallback() {
        let tmp = std::env::temp_dir().join("rustdefend_test_ws_single");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("src")).unwrap();

        fs::write(
            tmp.join("Cargo.toml"),
            r#"
[package]
name = "my-solana-app"
version = "0.1.0"

[dependencies]
solana-program = "1.18"
"#,
        )
        .unwrap();
        fs::write(tmp.join("src/lib.rs"), "// code").unwrap();

        let chain_map = build_workspace_chain_map(&tmp);
        let chains = chains_for_file(&chain_map, &tmp.join("src/lib.rs"), &[]);
        assert_eq!(chains, vec![Chain::Solana]);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_find_crate_root_deeply_nested() {
        let tmp = std::env::temp_dir().join("rustdefend_test_ws_nested");
        let _ = fs::remove_dir_all(&tmp);
        let deep = tmp.join("a/b/c/d");
        fs::create_dir_all(&deep).unwrap();
        fs::write(
            tmp.join("a/b/Cargo.toml"),
            "[package]\nname = \"deep\"\nversion = \"0.1.0\"",
        )
        .unwrap();

        let root = find_crate_root(&deep.join("main.rs"));
        assert!(root.is_some());
        let root = root.unwrap();
        // The root should end at a/b (where Cargo.toml is)
        assert!(root.ends_with("a/b") || root.to_string_lossy().contains("a/b"));

        let _ = fs::remove_dir_all(&tmp);
    }
}
