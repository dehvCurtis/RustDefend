use std::path::PathBuf;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;

pub struct SupplyChainDetector;

impl Detector for SupplyChainDetector {
    fn id(&self) -> &'static str {
        "DEP-002"
    }
    fn name(&self) -> &'static str {
        "supply-chain-risk"
    }
    fn description(&self) -> &'static str {
        "Detects wildcard versions, unpinned git deps, and known-malicious crate names in Cargo.toml"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn confidence(&self) -> Confidence {
        Confidence::High
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    } // Listed under Solana but applies cross-chain

    fn detect(&self, _ctx: &ScanContext) -> Vec<Finding> {
        // DEP-002 operates on Cargo.toml, not .rs files
        // Actual detection happens via detect_cargo_toml() called from Scanner
        Vec::new()
    }
}

const KNOWN_MALICIOUS_CRATES: &[&str] = &[
    "rustdecimal",
    "faster_log",
    "async_println",
    "finch-rust",
    "finch-rst",
    "sha-rust",
    "sha-rst",
    "finch_cli_rust",
    "polymarket-clients-sdk",
    "polymarket-client-sdks",
];

impl SupplyChainDetector {
    pub fn detect_cargo_toml(&self, cargo_toml_path: &PathBuf) -> Vec<Finding> {
        let content = match std::fs::read_to_string(cargo_toml_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let parsed: toml::Value = match content.parse() {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let mut findings = Vec::new();

        // Check [dependencies] for wildcards, unpinned git, and malicious crates
        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_table()) {
            self.check_deps(&content, cargo_toml_path, deps, false, &mut findings);
        }

        // Check [dev-dependencies] - only for malicious crates and unpinned git
        // (crates.io allows wildcards in dev-dependencies)
        if let Some(deps) = parsed.get("dev-dependencies").and_then(|v| v.as_table()) {
            self.check_deps(&content, cargo_toml_path, deps, true, &mut findings);
        }

        // Check [workspace.dependencies]
        if let Some(workspace) = parsed.get("workspace") {
            if let Some(deps) = workspace.get("dependencies").and_then(|v| v.as_table()) {
                self.check_deps(&content, cargo_toml_path, deps, false, &mut findings);
            }
        }

        findings
    }

    fn check_deps(
        &self,
        content: &str,
        path: &PathBuf,
        deps: &toml::map::Map<String, toml::Value>,
        is_dev: bool,
        findings: &mut Vec<Finding>,
    ) {
        for (name, value) in deps {
            let line = find_dep_line(content, name);

            // Check for known malicious crate names (exact match)
            if KNOWN_MALICIOUS_CRATES.contains(&name.as_str()) {
                findings.push(Finding {
                    detector_id: "DEP-002".to_string(),
                    name: "supply-chain-risk".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    message: format!(
                        "Known malicious crate detected: '{}' (typosquatting/supply chain attack)",
                        name
                    ),
                    file: path.clone(),
                    line,
                    column: 1,
                    snippet: format!("{} = ...", name),
                    recommendation: format!(
                        "Remove '{}' immediately. This is a known malicious crate used in supply chain attacks",
                        name
                    ),
                    chain: Chain::Solana,
                });
                continue;
            }

            match value {
                toml::Value::String(version) => {
                    // Skip dev-deps for wildcard detection
                    if !is_dev {
                        self.check_wildcard_version(content, path, name, version, line, findings);
                    }
                }
                toml::Value::Table(t) => {
                    // Skip path dependencies (local, not supply chain)
                    if t.contains_key("path") {
                        continue;
                    }

                    // Skip workspace = true (inherited version)
                    if t.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
                        continue;
                    }

                    // Check git deps without rev or tag
                    if t.contains_key("git") {
                        let has_rev = t.contains_key("rev");
                        let has_tag = t.contains_key("tag");
                        if !has_rev && !has_tag {
                            findings.push(Finding {
                                detector_id: "DEP-002".to_string(),
                                name: "supply-chain-risk".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                message: format!(
                                    "Unpinned git dependency: '{}' has no rev or tag (mutable reference)",
                                    name
                                ),
                                file: path.clone(),
                                line,
                                column: 1,
                                snippet: content
                                    .lines()
                                    .nth(line.saturating_sub(1))
                                    .unwrap_or("")
                                    .trim()
                                    .to_string(),
                                recommendation: format!(
                                    "Pin '{}' with rev = \"<commit-hash>\" or tag = \"<version>\" to prevent supply chain attacks via branch mutation",
                                    name
                                ),
                                chain: Chain::Solana,
                            });
                        }
                        continue;
                    }

                    // Check version field for wildcards (non-dev only)
                    if !is_dev {
                        if let Some(version) = t.get("version").and_then(|v| v.as_str()) {
                            self.check_wildcard_version(
                                content,
                                path,
                                name,
                                &version.to_string(),
                                line,
                                findings,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn check_wildcard_version(
        &self,
        content: &str,
        path: &PathBuf,
        name: &str,
        version: &str,
        line: usize,
        findings: &mut Vec<Finding>,
    ) {
        let is_wildcard = version == "*"
            || version.ends_with(".*")
            || version == ">= 0"
            || version == "> 0"
            || version.starts_with(">= 0.")
            || version.starts_with("> 0.");

        if is_wildcard {
            findings.push(Finding {
                detector_id: "DEP-002".to_string(),
                name: "supply-chain-risk".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                message: format!(
                    "Wildcard version for '{}': \"{}\" allows any version including malicious releases",
                    name, version
                ),
                file: path.clone(),
                line,
                column: 1,
                snippet: content
                    .lines()
                    .nth(line.saturating_sub(1))
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                recommendation: format!(
                    "Pin '{}' to a specific version range (e.g., \"1.0\" or \"^1.2.3\")",
                    name
                ),
                chain: Chain::Solana,
            });
        }
    }
}

fn find_dep_line(content: &str, crate_name: &str) -> usize {
    for (i, line) in content.lines().enumerate() {
        if line.trim_start().starts_with(crate_name) {
            return i + 1;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn run_detector(cargo_toml: &str) -> Vec<Finding> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("rustdefend_test_sc_{}.toml", id));
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(cargo_toml.as_bytes()).unwrap();
        let results = SupplyChainDetector.detect_cargo_toml(&tmp);
        let _ = std::fs::remove_file(&tmp);
        results
    }

    #[test]
    fn test_detects_wildcard_version() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dependencies]
some-crate = "*"
"#;
        let findings = run_detector(cargo_toml);
        assert!(!findings.is_empty(), "Should detect wildcard version");
        assert_eq!(findings[0].detector_id, "DEP-002");
        assert!(findings[0].message.contains("Wildcard"));
    }

    #[test]
    fn test_detects_known_malicious_crate() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dependencies]
rustdecimal = "0.3.1"
"#;
        let findings = run_detector(cargo_toml);
        assert!(!findings.is_empty(), "Should detect malicious crate");
        assert!(findings[0].message.contains("malicious"));
    }

    #[test]
    fn test_detects_unpinned_git_dep() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dependencies]
my-lib = { git = "https://github.com/example/lib", branch = "main" }
"#;
        let findings = run_detector(cargo_toml);
        assert!(!findings.is_empty(), "Should detect unpinned git dep");
        assert!(findings[0].message.contains("Unpinned"));
    }

    #[test]
    fn test_no_finding_for_path_deps() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dependencies]
my-lib = { path = "../my-lib" }
"#;
        let findings = run_detector(cargo_toml);
        assert!(findings.is_empty(), "Should not flag path dependencies");
    }

    #[test]
    fn test_no_finding_for_pinned_git() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dependencies]
my-lib = { git = "https://github.com/example/lib", rev = "abc123" }
another = { git = "https://github.com/example/other", tag = "v1.0.0" }
"#;
        let findings = run_detector(cargo_toml);
        assert!(findings.is_empty(), "Should not flag pinned git deps");
    }

    #[test]
    fn test_detects_partial_wildcard() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dependencies]
some-crate = "1.*"
"#;
        let findings = run_detector(cargo_toml);
        assert!(!findings.is_empty(), "Should detect partial wildcard");
    }

    #[test]
    fn test_skips_dev_deps_wildcards() {
        let cargo_toml = r#"
[package]
name = "my-contract"
version = "0.1.0"

[dev-dependencies]
test-helper = "*"
"#;
        let findings = run_detector(cargo_toml);
        assert!(
            findings.is_empty(),
            "Should skip wildcard in dev-dependencies"
        );
    }
}
