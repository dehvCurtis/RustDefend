use std::path::Path;

use serde::Deserialize;

/// Project-level configuration loaded from `.rustdefend.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProjectConfig {
    /// Detector IDs to ignore project-wide (e.g., ["SOL-003", "CW-001"]).
    #[serde(default)]
    pub ignore: Vec<String>,

    /// File patterns to skip entirely (glob patterns, e.g., ["generated/**", "vendor/**"]).
    #[serde(default)]
    pub ignore_files: Vec<String>,

    /// Optional minimum severity level (critical, high, medium, low).
    pub min_severity: Option<String>,

    /// Optional minimum confidence level (high, medium, low).
    pub min_confidence: Option<String>,
}

/// Load project configuration from a TOML file.
pub fn load_project_config(path: &Path) -> anyhow::Result<ProjectConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: ProjectConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Try to load config from `.rustdefend.toml` in the given directory, or return defaults.
pub fn load_config_or_default(scan_root: &Path) -> ProjectConfig {
    let config_path = scan_root.join(".rustdefend.toml");
    if config_path.exists() {
        load_project_config(&config_path).unwrap_or_default()
    } else {
        ProjectConfig::default()
    }
}

/// Check if a file path matches any of the ignore patterns.
pub fn file_is_ignored(file_path: &Path, scan_root: &Path, patterns: &[String]) -> bool {
    let relative = file_path.strip_prefix(scan_root).unwrap_or(file_path);
    let relative_str = relative.to_string_lossy();

    for pattern in patterns {
        if matches_glob_pattern(&relative_str, pattern) {
            return true;
        }
    }
    false
}

/// Simple glob matching supporting `*` and `**` patterns.
fn matches_glob_pattern(path: &str, pattern: &str) -> bool {
    // Normalize separators
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");

    if pattern.contains("**") {
        // "generated/**" matches any path starting with "generated/"
        let prefix = pattern.replace("/**", "").replace("**", "");
        let prefix = prefix.trim_end_matches('/');
        if path.starts_with(prefix) {
            return true;
        }
        // Also check if any path component matches
        return path.contains(&format!("/{}/", prefix))
            || path.starts_with(&format!("{}/", prefix));
    }

    if pattern.contains('*') {
        // Simple wildcard: "*.generated.rs" matches "foo.generated.rs"
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let (prefix, suffix) = (parts[0], parts[1]);
            let file_name = path.rsplit('/').next().unwrap_or(&path);
            return file_name.starts_with(prefix) && file_name.ends_with(suffix);
        }
    }

    // Exact match
    path == pattern
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_config_ignore_detectors() {
        let toml = r#"
ignore = ["SOL-003", "CW-001"]
ignore_files = ["generated/**", "vendor/**"]
min_severity = "high"
"#;
        let config: ProjectConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.ignore, vec!["SOL-003", "CW-001"]);
        assert_eq!(config.ignore_files, vec!["generated/**", "vendor/**"]);
        assert_eq!(config.min_severity, Some("high".to_string()));
        assert_eq!(config.min_confidence, None);
    }

    #[test]
    fn test_file_is_ignored_glob() {
        let scan_root = Path::new("/project");

        assert!(file_is_ignored(
            &PathBuf::from("/project/generated/types.rs"),
            scan_root,
            &["generated/**".to_string()]
        ));

        assert!(file_is_ignored(
            &PathBuf::from("/project/vendor/lib/mod.rs"),
            scan_root,
            &["vendor/**".to_string()]
        ));

        assert!(!file_is_ignored(
            &PathBuf::from("/project/src/lib.rs"),
            scan_root,
            &["generated/**".to_string()]
        ));
    }

    #[test]
    fn test_missing_config_returns_defaults() {
        let config = load_config_or_default(Path::new("/nonexistent"));
        assert!(config.ignore.is_empty());
        assert!(config.ignore_files.is_empty());
        assert!(config.min_severity.is_none());
    }

    #[test]
    fn test_load_config_file() {
        let tmp = std::env::temp_dir().join("rustdefend_config_test.toml");
        std::fs::write(
            &tmp,
            r#"
ignore = ["SOL-001"]
ignore_files = ["test/**"]
"#,
        )
        .unwrap();

        let config = load_project_config(&tmp).unwrap();
        assert_eq!(config.ignore, vec!["SOL-001"]);
        assert_eq!(config.ignore_files, vec!["test/**"]);

        let _ = std::fs::remove_file(&tmp);
    }
}
