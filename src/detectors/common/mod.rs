pub mod outdated_deps;
pub mod supply_chain;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(outdated_deps::OutdatedDepsDetector));
    detectors.push(Box::new(supply_chain::SupplyChainDetector));
}
