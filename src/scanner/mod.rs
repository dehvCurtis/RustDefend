pub mod context;
pub mod finding;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::detectors::common::outdated_deps::OutdatedDepsDetector;
use crate::detectors::common::proc_macro_risk::ProcMacroRiskDetector;
use crate::detectors::common::supply_chain::SupplyChainDetector;
use crate::detectors::DetectorRegistry;
use crate::rules::parser::CustomRule;
use crate::utils::call_graph;
use crate::utils::chain_detect;
use crate::utils::workspace;
use context::ScanContext;
use finding::{Chain, Confidence, Finding, Severity};

pub struct Scanner {
    registry: DetectorRegistry,
    filter_chains: Option<Vec<Chain>>,
    filter_severities: Option<Vec<Severity>>,
    filter_confidence: Option<Confidence>,
    filter_detectors: Option<Vec<String>>,
    ignore_files: Option<(Vec<String>, PathBuf)>,
    cache_path: Option<PathBuf>,
    cross_file: bool,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            registry: DetectorRegistry::new(),
            filter_chains: None,
            filter_severities: None,
            filter_confidence: None,
            filter_detectors: None,
            ignore_files: None,
            cache_path: None,
            cross_file: false,
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

    pub fn with_ignore_files(mut self, patterns: Vec<String>, scan_root: PathBuf) -> Self {
        self.ignore_files = Some((patterns, scan_root));
        self
    }

    pub fn with_cache(mut self, cache_path: PathBuf) -> Self {
        self.cache_path = Some(cache_path);
        self
    }

    pub fn with_custom_rules(mut self, rules: Vec<CustomRule>) -> Self {
        self.registry = DetectorRegistry::with_custom_rules(rules);
        self
    }

    pub fn with_cross_file(mut self, enabled: bool) -> Self {
        self.cross_file = enabled;
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

        // Build workspace chain map for per-file chain detection
        let chain_map = workspace::build_workspace_chain_map(path);

        // Load cache if incremental mode is enabled
        let cache = self
            .cache_path
            .as_ref()
            .map(|p| crate::cache::load_cache(p));

        // Collect all .rs files
        let mut rust_files: Vec<PathBuf> = Self::collect_rust_files(path);

        // Apply ignore_files filter
        if let Some((ref patterns, ref scan_root)) = self.ignore_files {
            rust_files.retain(|f| !crate::config::file_is_ignored(f, scan_root, patterns));
        }

        if rust_files.is_empty() {
            anyhow::bail!("No Rust source files found in {}", path.display());
        }

        // Get detectors for all possible chains (filtering happens per-file)
        let all_chains = vec![Chain::Solana, Chain::CosmWasm, Chain::Near, Chain::Ink];
        let detector_chains = if self.filter_chains.is_some() {
            &active_chains
        } else {
            &all_chains
        };
        let detectors = self.registry.get_detectors(
            detector_chains,
            self.filter_severities.as_deref(),
            self.filter_detectors.as_deref(),
        );

        // Cross-file mode: Pass 1 — parse all files and build crate call graph
        let crate_call_graph: Option<Arc<call_graph::CrateCallGraph>> = if self.cross_file {
            // Collect per-file call graphs (sequentially to avoid Send issues with syn types)
            let mut file_graphs: Vec<(PathBuf, String, syn::File, call_graph::CallGraph)> =
                Vec::new();
            for file_path in &rust_files {
                if let Ok(source) = std::fs::read_to_string(file_path) {
                    if let Ok(ast) = syn::parse_file(&source) {
                        let graph = call_graph::build_call_graph(&ast);
                        file_graphs.push((file_path.clone(), source, ast, graph));
                    }
                }
            }
            Some(Arc::new(call_graph::build_crate_call_graph(&file_graphs)))
        } else {
            None
        };

        // Pass 2: Process files in parallel (with optional crate call graph)
        let file_results: Vec<(PathBuf, u64, Vec<Finding>)> = rust_files
            .par_iter()
            .flat_map(|file_path| {
                // Check cache first
                let mtime = std::fs::metadata(file_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                if let Some(ref cache) = cache {
                    if let Some(cached_findings) = cache.lookup(file_path, mtime) {
                        return vec![(file_path.clone(), mtime, cached_findings)];
                    }
                }

                let source = match std::fs::read_to_string(file_path) {
                    Ok(s) => s,
                    Err(_) => return vec![],
                };

                let ast = match syn::parse_file(&source) {
                    Ok(ast) => ast,
                    Err(_) => return vec![],
                };

                // Build call graph once per file
                let graph = call_graph::build_call_graph(&ast);

                // Determine which chains apply to this specific file
                let file_chains = if self.filter_chains.is_some() {
                    active_chains.clone()
                } else {
                    workspace::chains_for_file(&chain_map, file_path, &active_chains)
                };

                // Run each chain's detectors against this file
                let mut file_findings = Vec::new();
                for &chain in &file_chains {
                    let mut ctx = ScanContext::new(
                        file_path.clone(),
                        source.clone(),
                        ast.clone(),
                        chain,
                        graph.clone(),
                    );

                    if let Some(ref ccg) = crate_call_graph {
                        ctx = ctx.with_crate_call_graph(Arc::clone(ccg));
                    }

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
                vec![(file_path.clone(), mtime, file_findings)]
            })
            .collect();

        // Extract findings and update cache
        let mut findings: Vec<Finding> = Vec::new();
        let mut new_cache = if self.cache_path.is_some() {
            Some(crate::cache::ScanCache::new())
        } else {
            None
        };

        for (file_path, mtime, file_findings) in file_results {
            if let Some(ref mut c) = new_cache {
                c.store(file_path, mtime, file_findings.clone());
            }
            findings.extend(file_findings);
        }

        // Save updated cache
        if let (Some(ref cache_path), Some(cache)) = (&self.cache_path, new_cache) {
            let _ = crate::cache::save_cache(&cache, cache_path);
        }

        // Run DEP-001, DEP-002, and DEP-004 on Cargo.toml files
        let dep_detector = OutdatedDepsDetector;
        let sc_detector = SupplyChainDetector;
        let pm_detector = ProcMacroRiskDetector;
        let cargo_tomls = Self::collect_cargo_tomls(path);
        for cargo_toml in &cargo_tomls {
            let dep_findings = dep_detector.detect_cargo_toml(cargo_toml);
            findings.extend(dep_findings);
            let sc_findings = sc_detector.detect_cargo_toml(cargo_toml);
            findings.extend(sc_findings);
            let pm_findings = pm_detector.detect_cargo_toml(cargo_toml);
            findings.extend(pm_findings);
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
