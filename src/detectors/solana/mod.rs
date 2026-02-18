mod account_confusion;
mod account_data_matching;
mod arbitrary_cpi;
mod checked_arithmetic_unwrap;
mod cpi_reentrancy;
mod duplicate_mutable_accounts;
mod init_if_needed;
mod insecure_account_close;
mod integer_overflow;
mod lookup_table;
mod missing_owner;
mod missing_rent_exempt;
mod missing_signer;
mod pda_issues;
mod priority_fee;
mod remaining_accounts;
mod token_extensions;
mod unchecked_return;
mod unsafe_pda_seeds;
mod unsafe_reallocation;
mod unvalidated_sysvar;

use super::Detector;

pub fn register(detectors: &mut Vec<Box<dyn Detector>>) {
    detectors.push(Box::new(missing_signer::MissingSignerDetector));
    detectors.push(Box::new(missing_owner::MissingOwnerDetector));
    detectors.push(Box::new(integer_overflow::IntegerOverflowDetector));
    detectors.push(Box::new(account_confusion::AccountConfusionDetector));
    detectors.push(Box::new(
        insecure_account_close::InsecureAccountCloseDetector,
    ));
    detectors.push(Box::new(arbitrary_cpi::ArbitraryCpiDetector));
    detectors.push(Box::new(pda_issues::PdaIssuesDetector));
    detectors.push(Box::new(unchecked_return::UncheckedReturnDetector));
    detectors.push(Box::new(cpi_reentrancy::CpiReentrancyDetector));
    detectors.push(Box::new(unsafe_pda_seeds::UnsafePdaSeedsDetector));
    detectors.push(Box::new(missing_rent_exempt::MissingRentExemptDetector));
    detectors.push(Box::new(token_extensions::TokenExtensionsDetector));
    detectors.push(Box::new(remaining_accounts::RemainingAccountsDetector));
    detectors.push(Box::new(init_if_needed::InitIfNeededDetector));
    detectors.push(Box::new(lookup_table::LookupTableDetector));
    detectors.push(Box::new(priority_fee::PriorityFeeDetector));
    detectors.push(Box::new(account_data_matching::AccountDataMatchingDetector));
    detectors.push(Box::new(unsafe_reallocation::UnsafeReallocationDetector));
    detectors.push(Box::new(
        duplicate_mutable_accounts::DuplicateMutableAccountsDetector,
    ));
    detectors.push(Box::new(
        checked_arithmetic_unwrap::CheckedArithmeticUnwrapDetector,
    ));
    detectors.push(Box::new(unvalidated_sysvar::UnvalidatedSysvarDetector));
}
