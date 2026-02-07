pub mod json;
pub mod sarif;
pub mod text;

use crate::scanner::finding::Finding;
use anyhow::Result;

pub trait Reporter {
    fn render(&self, findings: &[Finding]) -> Result<String>;
}
