pub mod build_script;
pub mod outdated_deps;
pub mod proc_macro_risk;
pub mod supply_chain;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(outdated_deps::OutdatedDepsDetector));
    detectors.push(Box::new(supply_chain::SupplyChainDetector));
    detectors.push(Box::new(build_script::BuildScriptDetector));
    detectors.push(Box::new(proc_macro_risk::ProcMacroRiskDetector));
}
