use serde::Serialize;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Solana,
    CosmWasm,
    Near,
    Ink,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Solana => write!(f, "Solana"),
            Chain::CosmWasm => write!(f, "CosmWasm"),
            Chain::Near => write!(f, "NEAR"),
            Chain::Ink => write!(f, "ink!"),
        }
    }
}

impl Chain {
    pub fn from_str_loose(s: &str) -> Option<Chain> {
        match s.to_lowercase().as_str() {
            "solana" | "sol" => Some(Chain::Solana),
            "cosmwasm" | "cw" | "cosmos" => Some(Chain::CosmWasm),
            "near" => Some(Chain::Near),
            "ink" | "ink!" | "polkadot" => Some(Chain::Ink),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
        }
    }
}

impl Severity {
    pub fn from_str_loose(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "critical" | "crit" => Some(Severity::Critical),
            "high" | "h" => Some(Severity::High),
            "medium" | "med" | "m" => Some(Severity::Medium),
            "low" | "l" => Some(Severity::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low = 0,
    Medium = 1,
    High = 2,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::High => write!(f, "High"),
            Confidence::Medium => write!(f, "Medium"),
            Confidence::Low => write!(f, "Low"),
        }
    }
}

impl Confidence {
    pub fn from_str_loose(s: &str) -> Option<Confidence> {
        match s.to_lowercase().as_str() {
            "high" | "h" => Some(Confidence::High),
            "medium" | "med" | "m" => Some(Confidence::Medium),
            "low" | "l" => Some(Confidence::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub detector_id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub recommendation: String,
    pub chain: Chain,
}
