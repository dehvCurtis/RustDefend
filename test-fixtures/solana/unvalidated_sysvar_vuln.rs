// Test fixture: SOL-021 unvalidated-sysvar
// Vulnerable: sysvar passed as AccountInfo without from_account_info() or Sysvar::get()

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;

pub fn process_with_clock(
    accounts: &[AccountInfo],
    clock_info: &AccountInfo,
) -> Result<(), ProgramError> {
    // Missing: should use Clock::from_account_info(clock_info)? or Clock::get()?
    // An attacker could pass a fake account instead of the real Clock sysvar
    let data = clock_info.try_borrow_data()?;
    let timestamp = u64::from_le_bytes(data[32..40].try_into().unwrap());
    Ok(())
}

pub fn check_rent(rent_account: &AccountInfo, target: &AccountInfo) -> Result<(), ProgramError> {
    // Missing: should use Rent::from_account_info() or Rent::get()
    let data = rent_account.try_borrow_data()?;
    Ok(())
}
