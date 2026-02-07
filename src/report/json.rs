use anyhow::Result;

use crate::scanner::finding::Finding;
use super::Reporter;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn render(&self, findings: &[Finding]) -> Result<String> {
        Ok(serde_json::to_string_pretty(findings)?)
    }
}
