use std::path::PathBuf;

use crate::scanner::finding::Chain;

pub struct ScanContext {
    pub file_path: PathBuf,
    pub source: String,
    pub ast: syn::File,
    pub chain: Chain,
}

impl ScanContext {
    pub fn new(file_path: PathBuf, source: String, ast: syn::File, chain: Chain) -> Self {
        Self {
            file_path,
            source,
            ast,
            chain,
        }
    }

    /// Returns the source line at 1-based line number.
    pub fn line_text(&self, line: usize) -> &str {
        self.source
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or("")
    }

    /// Check if a given line has a rustdefend-ignore comment.
    pub fn is_suppressed(&self, line: usize, detector_id: &str) -> bool {
        let text = self.line_text(line);
        if text.contains("rustdefend-ignore") {
            // Check for blanket ignore
            if !text.contains('[') {
                return true;
            }
            // Check for specific detector ignore: // rustdefend-ignore[SOL-001]
            if text.contains(&format!("rustdefend-ignore[{}]", detector_id)) {
                return true;
            }
        }
        // Also check the line above
        if line > 1 {
            let prev = self.line_text(line - 1);
            if prev.contains("rustdefend-ignore") {
                if !prev.contains('[') {
                    return true;
                }
                if prev.contains(&format!("rustdefend-ignore[{}]", detector_id)) {
                    return true;
                }
            }
        }
        false
    }
}
