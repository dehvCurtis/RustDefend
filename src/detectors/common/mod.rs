pub mod outdated_deps;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(outdated_deps::OutdatedDepsDetector));
}
