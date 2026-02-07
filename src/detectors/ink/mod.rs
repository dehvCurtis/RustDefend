mod reentrancy;
mod integer_overflow;
mod missing_caller_check;
mod timestamp_dependence;
mod unbounded_storage;
mod cross_contract;
mod panic_usage;
mod error_handling;
mod unsafe_delegate_call;
mod missing_payable_check;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(reentrancy::ReentrancyDetector));
    detectors.push(Box::new(integer_overflow::IntegerOverflowDetector));
    detectors.push(Box::new(missing_caller_check::MissingCallerCheckDetector));
    detectors.push(Box::new(timestamp_dependence::TimestampDependenceDetector));
    detectors.push(Box::new(unbounded_storage::UnboundedStorageDetector));
    detectors.push(Box::new(cross_contract::CrossContractDetector));
    detectors.push(Box::new(panic_usage::PanicUsageDetector));
    detectors.push(Box::new(error_handling::ErrorHandlingDetector));
    detectors.push(Box::new(unsafe_delegate_call::UnsafeDelegateCallDetector));
    detectors.push(Box::new(missing_payable_check::MissingPayableCheckDetector));
}
