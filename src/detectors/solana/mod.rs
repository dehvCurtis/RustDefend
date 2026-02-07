mod missing_signer;
mod missing_owner;
mod integer_overflow;
mod account_confusion;
mod insecure_account_close;
mod arbitrary_cpi;
mod pda_issues;
mod unchecked_return;
mod cpi_reentrancy;
mod unsafe_pda_seeds;
mod missing_rent_exempt;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(missing_signer::MissingSignerDetector));
    detectors.push(Box::new(missing_owner::MissingOwnerDetector));
    detectors.push(Box::new(integer_overflow::IntegerOverflowDetector));
    detectors.push(Box::new(account_confusion::AccountConfusionDetector));
    detectors.push(Box::new(insecure_account_close::InsecureAccountCloseDetector));
    detectors.push(Box::new(arbitrary_cpi::ArbitraryCpiDetector));
    detectors.push(Box::new(pda_issues::PdaIssuesDetector));
    detectors.push(Box::new(unchecked_return::UncheckedReturnDetector));
    detectors.push(Box::new(cpi_reentrancy::CpiReentrancyDetector));
    detectors.push(Box::new(unsafe_pda_seeds::UnsafePdaSeedsDetector));
    detectors.push(Box::new(missing_rent_exempt::MissingRentExemptDetector));
}
