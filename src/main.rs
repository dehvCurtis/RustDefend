use std::path::Path;
use std::process;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use rustdefend::baseline;
use rustdefend::cli::{Cli, Commands};
use rustdefend::config;
use rustdefend::report::json::JsonReporter;
use rustdefend::report::sarif::SarifReporter;
use rustdefend::report::text::TextReporter;
use rustdefend::report::Reporter;
use rustdefend::scanner::finding::{Chain, Confidence, Severity};
use rustdefend::scanner::Scanner;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::ListDetectors(args) => run_list_detectors(args),
    }
}

fn run_scan(args: rustdefend::cli::ScanArgs) -> Result<()> {
    let path = Path::new(&args.path);
    if !path.exists() {
        eprintln!(
            "{} Path does not exist: {}",
            "Error:".red().bold(),
            args.path
        );
        process::exit(2);
    }

    // Load project config
    let project_config = if let Some(ref config_path) = args.config {
        config::load_project_config(Path::new(config_path)).unwrap_or_else(|e| {
            eprintln!(
                "{} Failed to load config: {}",
                "Warning:".yellow().bold(),
                e
            );
            config::ProjectConfig::default()
        })
    } else {
        config::load_config_or_default(path)
    };

    // Load custom rules if provided
    let mut scanner = if let Some(ref rules_path) = args.rules {
        let rules = rustdefend::rules::load_rules(Path::new(rules_path)).unwrap_or_else(|e| {
            eprintln!("{} Failed to load rules: {}", "Warning:".yellow().bold(), e);
            Vec::new()
        });
        if !rules.is_empty() {
            eprintln!(
                "{} Loaded {} custom rules from {}",
                "Info:".blue().bold(),
                rules.len(),
                rules_path
            );
        }
        Scanner::new().with_custom_rules(rules)
    } else {
        Scanner::new()
    };

    // Apply chain filter
    if let Some(ref chain_str) = args.chain {
        let chains: Vec<Chain> = chain_str
            .split(',')
            .filter_map(|s| Chain::from_str_loose(s.trim()))
            .collect();
        if chains.is_empty() {
            eprintln!("{} Unknown chain: {}", "Error:".red().bold(), chain_str);
            process::exit(2);
        }
        scanner = scanner.with_chain_filter(chains);
    }

    // Apply severity filter (CLI flag takes precedence over config)
    if let Some(ref sev_str) = args.severity {
        let sevs: Vec<Severity> = sev_str
            .split(',')
            .filter_map(|s| Severity::from_str_loose(s.trim()))
            .collect();
        if !sevs.is_empty() {
            scanner = scanner.with_severity_filter(sevs);
        }
    }

    // Apply confidence filter (CLI flag takes precedence over config)
    if let Some(ref conf_str) = args.confidence {
        if let Some(conf) = Confidence::from_str_loose(conf_str.trim()) {
            scanner = scanner.with_confidence_filter(conf);
        }
    }

    // Apply detector filter
    if let Some(ref det_str) = args.detector {
        let dets: Vec<String> = det_str
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .collect();
        scanner = scanner.with_detector_filter(dets);
    }

    // Apply config ignore_files to scanner
    if !project_config.ignore_files.is_empty() {
        scanner =
            scanner.with_ignore_files(project_config.ignore_files.clone(), path.to_path_buf());
    }

    // Apply cross-file analysis
    if args.cross_file {
        scanner = scanner.with_cross_file(true);
    }

    // Apply incremental cache
    if args.incremental {
        let cache_path = args
            .cache_path
            .as_ref()
            .map(|p| std::path::PathBuf::from(p))
            .unwrap_or_else(|| path.join(".rustdefend.cache.json"));
        scanner = scanner.with_cache(cache_path);
    }

    let mut findings = scanner.scan(path)?;

    // Apply config-level detector ignores
    if !project_config.ignore.is_empty() {
        findings.retain(|f| !project_config.ignore.contains(&f.detector_id));
    }

    // Apply config-level min_severity
    if let Some(ref min_sev) = project_config.min_severity {
        if let Some(min) = Severity::from_str_loose(min_sev) {
            findings.retain(|f| f.severity >= min);
        }
    }

    // Apply config-level min_confidence
    if let Some(ref min_conf) = project_config.min_confidence {
        if let Some(min) = Confidence::from_str_loose(min_conf) {
            findings.retain(|f| f.confidence >= min);
        }
    }

    // Save baseline if requested
    if let Some(ref save_path) = args.save_baseline {
        baseline::save_baseline(&findings, path, Path::new(save_path))?;
        eprintln!(
            "{} Baseline saved with {} findings to {}",
            "Info:".blue().bold(),
            findings.len(),
            save_path
        );
    }

    // Diff against baseline if provided
    let findings = if let Some(ref baseline_path) = args.baseline {
        let bl = baseline::load_baseline(Path::new(baseline_path))?;
        let (new_findings, suppressed) = baseline::diff_against_baseline(&findings, &bl, path);
        eprintln!(
            "{} {} findings suppressed by baseline",
            "Info:".blue().bold(),
            suppressed
        );
        new_findings
    } else {
        findings
    };

    if args.quiet {
        process::exit(if findings.is_empty() { 0 } else { 1 });
    }

    let reporter: Box<dyn Reporter> = match args.format.as_str() {
        "json" => Box::new(JsonReporter),
        "sarif" => Box::new(SarifReporter),
        _ => Box::new(TextReporter),
    };

    let output = reporter.render(&findings)?;
    println!("{}", output);

    if !findings.is_empty() {
        process::exit(1);
    }

    Ok(())
}

fn run_list_detectors(args: rustdefend::cli::ListDetectorsArgs) -> Result<()> {
    let scanner = Scanner::new();

    let chain_filter: Option<Vec<Chain>> = args.chain.as_ref().map(|c| {
        c.split(',')
            .filter_map(|s| Chain::from_str_loose(s.trim()))
            .collect()
    });

    let detectors = scanner.list_detectors(chain_filter.as_deref());

    println!(
        "\n{}\n",
        format!("RustDefend Detectors ({})", detectors.len()).bold()
    );
    println!(
        "  {:<12} {:<30} {:<10} {:<10} {:<10} {}",
        "ID".bold(),
        "Name".bold(),
        "Chain".bold(),
        "Severity".bold(),
        "Confidence".bold(),
        "Description".bold()
    );
    println!("  {}", "-".repeat(110));

    for d in &detectors {
        println!(
            "  {:<12} {:<30} {:<10} {:<10} {:<10} {}",
            d.id, d.name, d.chain, d.severity, d.confidence, d.description
        );
    }

    println!("\n  Total: {} detectors\n", detectors.len());
    Ok(())
}
