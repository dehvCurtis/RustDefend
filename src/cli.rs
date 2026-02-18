use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rustdefend",
    about = "Static security scanner for Rust smart contracts",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan Rust smart contract source code for vulnerabilities
    Scan(ScanArgs),
    /// List all available detectors
    #[command(name = "list-detectors")]
    ListDetectors(ListDetectorsArgs),
}

#[derive(Parser)]
pub struct ScanArgs {
    /// Path to the project or file to scan
    pub path: String,

    /// Force a specific chain (solana, cosmwasm, near, ink)
    #[arg(long)]
    pub chain: Option<String>,

    /// Filter by severity (critical, high, medium, low) - comma-separated
    #[arg(long)]
    pub severity: Option<String>,

    /// Minimum confidence level (high, medium, low)
    #[arg(long)]
    pub confidence: Option<String>,

    /// Output format (text, json, sarif)
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Only run specific detectors (comma-separated IDs, e.g. SOL-001,CW-003)
    #[arg(long)]
    pub detector: Option<String>,

    /// Quiet mode - only output exit code (0 = clean, 1 = findings)
    #[arg(long, short)]
    pub quiet: bool,

    /// Compare against a baseline file and only report new findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Save current findings as a baseline file
    #[arg(long)]
    pub save_baseline: Option<String>,

    /// Path to project config file (default: .rustdefend.toml in scan root)
    #[arg(long)]
    pub config: Option<String>,

    /// Enable incremental scanning with cached results
    #[arg(long)]
    pub incremental: bool,

    /// Path to the scan cache file (default: <scan_root>/.rustdefend.cache.json)
    #[arg(long)]
    pub cache_path: Option<String>,

    /// Path to custom rules file (TOML format)
    #[arg(long)]
    pub rules: Option<String>,

    /// Enable cross-file call graph analysis
    #[arg(long)]
    pub cross_file: bool,

    /// Enable type-aware analysis (AST-level type inference)
    #[arg(long)]
    pub type_aware: bool,
}

#[derive(Parser)]
pub struct ListDetectorsArgs {
    /// Filter by chain (solana, cosmwasm, near, ink)
    #[arg(long)]
    pub chain: Option<String>,
}
