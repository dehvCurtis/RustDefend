use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::scanner::finding::Finding;

/// A fingerprint for a finding that is stable across line number changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FindingFingerprint {
    pub detector_id: String,
    pub relative_file: String,
    pub context_name: String,
    pub snippet_prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u8,
    pub fingerprints: Vec<FindingFingerprint>,
}

impl FindingFingerprint {
    /// Create a fingerprint from a finding, using paths relative to scan_root.
    pub fn from_finding(finding: &Finding, scan_root: &Path) -> Self {
        let relative_file = finding
            .file
            .strip_prefix(scan_root)
            .unwrap_or(&finding.file)
            .to_string_lossy()
            .to_string();

        // Extract context name from message (e.g., "Function 'foo'" -> "foo")
        let context_name = extract_context_name(&finding.message);

        // First 60 chars of snippet, lowercased for stability
        let snippet_prefix = finding
            .snippet
            .chars()
            .take(60)
            .collect::<String>()
            .to_lowercase();

        Self {
            detector_id: finding.detector_id.clone(),
            relative_file,
            context_name,
            snippet_prefix,
        }
    }
}

/// Extract a function/context name from a finding message.
fn extract_context_name(message: &str) -> String {
    // Look for patterns like "Function 'name'" or "Method 'name'"
    if let Some(start) = message.find('\'') {
        if let Some(end) = message[start + 1..].find('\'') {
            return message[start + 1..start + 1 + end].to_string();
        }
    }
    String::new()
}

/// Save findings as a baseline file.
pub fn save_baseline(
    findings: &[Finding],
    scan_root: &Path,
    output_path: &Path,
) -> anyhow::Result<()> {
    let fingerprints: Vec<FindingFingerprint> = findings
        .iter()
        .map(|f| FindingFingerprint::from_finding(f, scan_root))
        .collect();

    let baseline = Baseline {
        version: 1,
        fingerprints,
    };

    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(output_path, json)?;
    Ok(())
}

/// Load a baseline from a JSON file.
pub fn load_baseline(path: &Path) -> anyhow::Result<Baseline> {
    let content = std::fs::read_to_string(path)?;
    let baseline: Baseline = serde_json::from_str(&content)?;
    Ok(baseline)
}

/// Diff findings against a baseline. Returns (new_findings, suppressed_count).
pub fn diff_against_baseline(
    findings: &[Finding],
    baseline: &Baseline,
    scan_root: &Path,
) -> (Vec<Finding>, usize) {
    let mut new_findings = Vec::new();
    let mut suppressed = 0;

    for finding in findings {
        let fp = FindingFingerprint::from_finding(finding, scan_root);
        if baseline.fingerprints.contains(&fp) {
            suppressed += 1;
        } else {
            new_findings.push(finding.clone());
        }
    }

    (new_findings, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::finding::*;
    use std::path::PathBuf;

    fn make_finding(detector_id: &str, file: &str, line: usize, message: &str) -> Finding {
        Finding {
            detector_id: detector_id.to_string(),
            name: "test".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            message: message.to_string(),
            file: PathBuf::from(file),
            line,
            column: 1,
            snippet: "let x = a + b;".to_string(),
            recommendation: "Fix it".to_string(),
            chain: Chain::Solana,
        }
    }

    #[test]
    fn test_fingerprint_stable_across_line_shifts() {
        let scan_root = Path::new("/project");
        let f1 = make_finding(
            "SOL-001",
            "/project/src/lib.rs",
            10,
            "Function 'withdraw' missing check",
        );
        let f2 = make_finding(
            "SOL-001",
            "/project/src/lib.rs",
            15,
            "Function 'withdraw' missing check",
        );

        let fp1 = FindingFingerprint::from_finding(&f1, scan_root);
        let fp2 = FindingFingerprint::from_finding(&f2, scan_root);

        assert_eq!(fp1, fp2, "Same fn different line should produce same fingerprint");
    }

    #[test]
    fn test_diff_empty_baseline_all_new() {
        let scan_root = Path::new("/project");
        let findings = vec![
            make_finding("SOL-001", "/project/src/lib.rs", 10, "Function 'a'"),
            make_finding("SOL-002", "/project/src/lib.rs", 20, "Function 'b'"),
        ];
        let baseline = Baseline {
            version: 1,
            fingerprints: vec![],
        };

        let (new_findings, suppressed) = diff_against_baseline(&findings, &baseline, scan_root);
        assert_eq!(new_findings.len(), 2);
        assert_eq!(suppressed, 0);
    }

    #[test]
    fn test_diff_full_baseline_all_suppressed() {
        let scan_root = Path::new("/project");
        let findings = vec![
            make_finding("SOL-001", "/project/src/lib.rs", 10, "Function 'a'"),
        ];

        let fingerprints = findings
            .iter()
            .map(|f| FindingFingerprint::from_finding(f, scan_root))
            .collect();
        let baseline = Baseline {
            version: 1,
            fingerprints,
        };

        let (new_findings, suppressed) = diff_against_baseline(&findings, &baseline, scan_root);
        assert_eq!(new_findings.len(), 0);
        assert_eq!(suppressed, 1);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let scan_root = Path::new("/project");
        let findings = vec![
            make_finding("SOL-001", "/project/src/lib.rs", 10, "Function 'foo'"),
        ];

        let tmp = std::env::temp_dir().join("rustdefend_baseline_test.json");
        save_baseline(&findings, scan_root, &tmp).unwrap();
        let loaded = load_baseline(&tmp).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.fingerprints.len(), 1);
        assert_eq!(loaded.fingerprints[0].detector_id, "SOL-001");

        let _ = std::fs::remove_file(&tmp);
    }
}
