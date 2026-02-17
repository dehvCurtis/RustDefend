pub mod context;
pub mod finding;

use std::path::{Path, PathBuf};

use anyhow::Result;
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::detectors::common::outdated_deps::OutdatedDepsDetector;
use crate::detectors::common::supply_chain::SupplyChainDetector;
use crate::detectors::DetectorRegistry;
use crate::utils::chain_detect;
use context::ScanContext;
use finding::{Chain, Confidence, Finding, Severity};

pub struct Scanner {
    registry: DetectorRegistry,
    filter_chains: Option<Vec<Chain>>,
    filter_severities: Option<Vec<Severity>>,
    filter_confidence: Option<Confidence>,
    filter_detectors: Option<Vec<String>>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            registry: DetectorRegistry::new(),
            filter_chains: None,
            filter_severities: None,
            filter_confidence: None,
            filter_detectors: None,
        }
    }

    pub fn with_chain_filter(mut self, chains: Vec<Chain>) -> Self {
        self.filter_chains = Some(chains);
        self
    }

    pub fn with_severity_filter(mut self, severities: Vec<Severity>) -> Self {
        self.filter_severities = Some(severities);
        self
    }

    pub fn with_confidence_filter(mut self, confidence: Confidence) -> Self {
        self.filter_confidence = Some(confidence);
        self
    }

    pub fn with_detector_filter(mut self, detectors: Vec<String>) -> Self {
        self.filter_detectors = Some(detectors);
        self
    }

    pub fn scan(&self, path: &Path) -> Result<Vec<Finding>> {
        // Detect chains from Cargo.toml
        let detected_chains = chain_detect::detect_chains(path);
        let active_chains: Vec<Chain> = if let Some(ref filter) = self.filter_chains {
            filter.clone()
        } else if !detected_chains.is_empty() {
            detected_chains
        } else {
            // If no chain detected, run all detectors
            vec![Chain::Solana, Chain::CosmWasm, Chain::Near, Chain::Ink]
        };

        // Collect all .rs files
        let rust_files: Vec<PathBuf> = Self::collect_rust_files(path);

        if rust_files.is_empty() {
            anyhow::bail!("No Rust source files found in {}", path.display());
        }

        // Get active detectors
        let detectors = self.registry.get_detectors(
            &active_chains,
            self.filter_severities.as_deref(),
            self.filter_detectors.as_deref(),
        );

        // Process files in parallel
        let findings: Vec<Finding> = rust_files
            .par_iter()
            .flat_map(|file_path| {
                let source = match std::fs::read_to_string(file_path) {
                    Ok(s) => s,
                    Err(_) => return vec![],
                };

                let ast = match syn::parse_file(&source) {
                    Ok(ast) => ast,
                    Err(_) => return vec![],
                };

                // Run each chain's detectors against this file
                let mut file_findings = Vec::new();
                for &chain in &active_chains {
                    let ctx =
                        ScanContext::new(file_path.clone(), source.clone(), ast.clone(), chain);

                    for detector in &detectors {
                        if detector.chain() != chain {
                            continue;
                        }
                        let mut results = detector.detect(&ctx);
                        // Filter suppressed findings
                        results.retain(|f| !ctx.is_suppressed(f.line, &f.detector_id));
                        file_findings.extend(results);
                    }
                }
                file_findings
            })
            .collect();

        // Run DEP-001 and DEP-002 on Cargo.toml files
        let mut findings = findings;
        let dep_detector = OutdatedDepsDetector;
        let sc_detector = SupplyChainDetector;
        let cargo_tomls = Self::collect_cargo_tomls(path);
        for cargo_toml in &cargo_tomls {
            let dep_findings = dep_detector.detect_cargo_toml(cargo_toml);
            findings.extend(dep_findings);
            let sc_findings = sc_detector.detect_cargo_toml(cargo_toml);
            findings.extend(sc_findings);
        }

        // Apply confidence filter
        let findings = if let Some(min_confidence) = self.filter_confidence {
            findings
                .into_iter()
                .filter(|f| f.confidence >= min_confidence)
                .collect()
        } else {
            findings
        };

        Ok(findings)
    }

    fn collect_rust_files(path: &Path) -> Vec<PathBuf> {
        if path.is_file() && path.extension().map_or(false, |e| e == "rs") {
            return vec![path.to_path_buf()];
        }

        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path().to_string_lossy();
                e.path().extension().map_or(false, |ext| ext == "rs")
                    && !p.contains("/target/")
                    && !p.contains("/tests/")
                    && !p.contains("/test/")
                    && !p.contains("/fuzz/")
                    && !p.ends_with("_test.rs")
                    && !p.ends_with("/tests.rs")
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    }

    fn collect_cargo_tomls(path: &Path) -> Vec<PathBuf> {
        if path.is_file() && path.file_name().map_or(false, |n| n == "Cargo.toml") {
            return vec![path.to_path_buf()];
        }

        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path().to_string_lossy();
                e.path().file_name().map_or(false, |n| n == "Cargo.toml") && !p.contains("/target/")
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    }

    pub fn list_detectors(&self, chain_filter: Option<&[Chain]>) -> Vec<DetectorInfo> {
        self.registry.list_detectors(chain_filter)
    }
}

pub struct DetectorInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub chain: Chain,
}
