use std::path::Path;
use std::process;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use rustdefend::cli::{Cli, Commands};
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
        eprintln!("{} Path does not exist: {}", "Error:".red().bold(), args.path);
        process::exit(2);
    }

    let mut scanner = Scanner::new();

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

    // Apply severity filter
    if let Some(ref sev_str) = args.severity {
        let sevs: Vec<Severity> = sev_str
            .split(',')
            .filter_map(|s| Severity::from_str_loose(s.trim()))
            .collect();
        if !sevs.is_empty() {
            scanner = scanner.with_severity_filter(sevs);
        }
    }

    // Apply confidence filter
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

    let findings = scanner.scan(path)?;

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
