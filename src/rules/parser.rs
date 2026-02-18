use serde::Deserialize;
use std::path::Path;

/// A set of custom rules loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct RuleSet {
    #[serde(rename = "rules", default)]
    pub rules: Vec<CustomRule>,
}

/// A single custom rule definition.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    /// Unique identifier (e.g., "CUSTOM-001").
    pub id: String,
    /// Human-readable name (e.g., "no-unsafe-blocks").
    pub name: String,
    /// Severity level: "critical", "high", "medium", "low".
    pub severity: String,
    /// Confidence level: "high", "medium", "low".
    pub confidence: String,
    /// Optional chain filter: "solana", "cosmwasm", "near", "ink". Defaults to all.
    pub chain: Option<String>,
    /// Substring pattern to match in function bodies.
    pub pattern: String,
    /// Message to display when the rule matches.
    pub message: String,
    /// Recommendation for fixing the issue.
    pub recommendation: String,
    /// Whether to exclude test functions (default: true).
    #[serde(default = "default_true")]
    pub exclude_tests: bool,
}

fn default_true() -> bool {
    true
}

/// Load custom rules from a TOML file.
pub fn load_rules(path: &Path) -> anyhow::Result<Vec<CustomRule>> {
    let content = std::fs::read_to_string(path)?;
    let rule_set: RuleSet = toml::from_str(&content)?;
    Ok(rule_set.rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rules_toml() {
        let toml = r#"
[[rules]]
id = "CUSTOM-001"
name = "no-unsafe-blocks"
severity = "high"
confidence = "medium"
chain = "solana"
pattern = "unsafe {"
message = "Unsafe block in smart contract code"
recommendation = "Remove or audit unsafe blocks"
exclude_tests = true

[[rules]]
id = "CUSTOM-002"
name = "no-unwrap"
severity = "medium"
confidence = "high"
pattern = ".unwrap()"
message = "unwrap() usage detected"
recommendation = "Use ? operator or proper error handling"
"#;
        let rule_set: RuleSet = toml::from_str(toml).unwrap();
        assert_eq!(rule_set.rules.len(), 2);
        assert_eq!(rule_set.rules[0].id, "CUSTOM-001");
        assert_eq!(rule_set.rules[0].chain, Some("solana".to_string()));
        assert_eq!(rule_set.rules[1].id, "CUSTOM-002");
        assert_eq!(rule_set.rules[1].chain, None);
        assert!(rule_set.rules[1].exclude_tests);
    }

    #[test]
    fn test_load_rules_from_file() {
        let tmp = std::env::temp_dir().join("rustdefend_rules_test.toml");
        std::fs::write(
            &tmp,
            r#"
[[rules]]
id = "CUSTOM-001"
name = "test-rule"
severity = "low"
confidence = "low"
pattern = "todo!"
message = "TODO found"
recommendation = "Complete the implementation"
"#,
        )
        .unwrap();

        let rules = load_rules(&tmp).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "todo!");

        let _ = std::fs::remove_file(&tmp);
    }
}
