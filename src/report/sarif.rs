use anyhow::Result;
use serde_json::json;

use super::Reporter;
use crate::scanner::finding::{Finding, Severity};

pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn render(&self, findings: &[Finding]) -> Result<String> {
        let rules: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| &f.detector_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .map(|id| {
                let finding = findings.iter().find(|f| &f.detector_id == id).unwrap();
                json!({
                    "id": id,
                    "name": finding.name,
                    "shortDescription": {
                        "text": finding.name
                    },
                    "fullDescription": {
                        "text": finding.message
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(&finding.severity)
                    }
                })
            })
            .collect();

        let results: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "ruleId": f.detector_id,
                    "level": severity_to_sarif_level(&f.severity),
                    "message": {
                        "text": format!("{}\nRecommendation: {}", f.message, f.recommendation)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file.display().to_string()
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column
                            }
                        }
                    }]
                })
            })
            .collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "RustDefend",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/rustdefend/rustdefend",
                        "rules": rules
                    }
                },
                "results": results
            }]
        });

        Ok(serde_json::to_string_pretty(&sarif)?)
    }
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}
