mod promise_reentrancy;
mod signer_vs_predecessor;
mod storage_staking;
mod unhandled_promise;
mod integer_overflow;
mod missing_private;
mod self_callback;
mod frontrunning;
mod unsafe_storage_keys;
mod missing_deposit_check;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(promise_reentrancy::PromiseReentrancyDetector));
    detectors.push(Box::new(signer_vs_predecessor::SignerVsPredecessorDetector));
    detectors.push(Box::new(storage_staking::StorageStakingDetector));
    detectors.push(Box::new(unhandled_promise::UnhandledPromiseDetector));
    detectors.push(Box::new(integer_overflow::IntegerOverflowDetector));
    detectors.push(Box::new(missing_private::MissingPrivateDetector));
    detectors.push(Box::new(self_callback::SelfCallbackDetector));
    detectors.push(Box::new(frontrunning::FrontrunningDetector));
    detectors.push(Box::new(unsafe_storage_keys::UnsafeStorageKeysDetector));
    detectors.push(Box::new(missing_deposit_check::MissingDepositCheckDetector));
}
