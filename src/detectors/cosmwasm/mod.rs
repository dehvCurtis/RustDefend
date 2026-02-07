mod integer_overflow;
mod reentrancy;
mod missing_sender_check;
mod storage_collision;
mod unchecked_response;
mod improper_error;
mod unbounded_iteration;
mod missing_address_validation;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(integer_overflow::IntegerOverflowDetector));
    detectors.push(Box::new(reentrancy::ReentrancyDetector));
    detectors.push(Box::new(missing_sender_check::MissingSenderCheckDetector));
    detectors.push(Box::new(storage_collision::StorageCollisionDetector));
    detectors.push(Box::new(unchecked_response::UncheckedResponseDetector));
    detectors.push(Box::new(improper_error::ImproperErrorDetector));
    detectors.push(Box::new(unbounded_iteration::UnboundedIterationDetector));
    detectors.push(Box::new(missing_address_validation::MissingAddressValidationDetector));
}
