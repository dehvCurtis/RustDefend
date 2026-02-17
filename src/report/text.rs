use anyhow::Result;
use colored::Colorize;

use super::Reporter;
use crate::scanner::finding::{Finding, Severity};

pub struct TextReporter;

impl Reporter for TextReporter {
    fn render(&self, findings: &[Finding]) -> Result<String> {
        if findings.is_empty() {
            return Ok("No findings detected.".green().to_string());
        }

        let mut output = String::new();

        // Group by severity
        let mut critical: Vec<&Finding> = Vec::new();
        let mut high: Vec<&Finding> = Vec::new();
        let mut medium: Vec<&Finding> = Vec::new();
        let mut low: Vec<&Finding> = Vec::new();

        for f in findings {
            match f.severity {
                Severity::Critical => critical.push(f),
                Severity::High => high.push(f),
                Severity::Medium => medium.push(f),
                Severity::Low => low.push(f),
            }
        }

        let groups: Vec<(&str, Vec<&Finding>)> = vec![
            ("CRITICAL", critical),
            ("HIGH", high),
            ("MEDIUM", medium),
            ("LOW", low),
        ];

        for (label, group) in &groups {
            if group.is_empty() {
                continue;
            }

            let header = format!("\n--- {} ({}) ---\n", label, group.len());
            let colored_header = match *label {
                "CRITICAL" => header.red().bold().to_string(),
                "HIGH" => header.yellow().bold().to_string(),
                "MEDIUM" => header.blue().bold().to_string(),
                "LOW" => header.dimmed().to_string(),
                _ => header,
            };
            output.push_str(&colored_header);

            for f in group {
                let title = f.name.replace('-', " ");
                let title = title
                    .split_whitespace()
                    .map(|w| {
                        let mut c = w.chars();
                        match c.next() {
                            None => String::new(),
                            Some(first) => first.to_uppercase().to_string() + c.as_str(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                output.push_str(&format!(
                    "\n  [{}] {} ({})\n",
                    f.detector_id.bold(),
                    title.bold(),
                    f.chain
                ));
                output.push_str(&format!("  {}\n", f.message));
                output.push_str(&format!(
                    "  {} {}:{}\n",
                    "-->".dimmed(),
                    f.file.display(),
                    f.line
                ));
                if !f.snippet.is_empty() {
                    output.push_str(&format!("  {} {}\n", "|".dimmed(), f.snippet.dimmed()));
                }
                output.push_str(&format!(
                    "  {} {}\n",
                    "Recommendation:".cyan(),
                    f.recommendation
                ));
                output.push_str(&format!(
                    "  {} {} | {} {}\n",
                    "Severity:".dimmed(),
                    f.severity,
                    "Confidence:".dimmed(),
                    f.confidence
                ));
            }
        }

        // Summary
        output.push_str(&format!(
            "\n{}\n",
            format!(
                "Summary: {} findings ({} critical, {} high, {} medium, {} low)",
                findings.len(),
                groups[0].1.len(),
                groups[1].1.len(),
                groups[2].1.len(),
                groups[3].1.len(),
            )
            .bold()
        ));

        Ok(output)
    }
}
