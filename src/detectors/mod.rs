pub mod common;
pub mod cosmwasm;
pub mod ink;
pub mod near;
pub mod solana;

use crate::rules::parser::CustomRule;
use crate::rules::CustomDetector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::{Chain, Confidence, Finding, Severity};
use crate::scanner::DetectorInfo;

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn confidence(&self) -> Confidence;
    fn chain(&self) -> Chain;
    fn detect(&self, ctx: &ScanContext) -> Vec<Finding>;
}

pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

        // Register all detectors from each chain module
        solana::register(&mut detectors);
        cosmwasm::register(&mut detectors);
        near::register(&mut detectors);
        ink::register(&mut detectors);
        common::register(&mut detectors);

        Self { detectors }
    }

    /// Create a registry with custom rules appended.
    pub fn with_custom_rules(custom_rules: Vec<CustomRule>) -> Self {
        let mut registry = Self::new();
        for rule in custom_rules {
            registry.detectors.push(Box::new(CustomDetector::new(rule)));
        }
        registry
    }

    pub fn get_detectors(
        &self,
        chains: &[Chain],
        severities: Option<&[Severity]>,
        detector_ids: Option<&[String]>,
    ) -> Vec<&dyn Detector> {
        self.detectors
            .iter()
            .filter(|d| chains.contains(&d.chain()))
            .filter(|d| severities.map_or(true, |sevs| sevs.contains(&d.severity())))
            .filter(|d| detector_ids.map_or(true, |ids| ids.iter().any(|id| id == d.id())))
            .map(|d| d.as_ref())
            .collect()
    }

    pub fn list_detectors(&self, chain_filter: Option<&[Chain]>) -> Vec<DetectorInfo> {
        self.detectors
            .iter()
            .filter(|d| chain_filter.map_or(true, |chains| chains.contains(&d.chain())))
            .map(|d| DetectorInfo {
                id: d.id(),
                name: d.name(),
                description: d.description(),
                severity: d.severity(),
                confidence: d.confidence(),
                chain: d.chain(),
            })
            .collect()
    }
}
