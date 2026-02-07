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
}

#[derive(Parser)]
pub struct ListDetectorsArgs {
    /// Filter by chain (solana, cosmwasm, near, ink)
    #[arg(long)]
    pub chain: Option<String>,
}
