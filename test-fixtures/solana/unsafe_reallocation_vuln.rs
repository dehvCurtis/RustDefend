// Test fixture: SOL-018 unsafe-account-reallocation
// Vulnerable: realloc without signer check and rent check

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;

pub fn resize_account(account: &AccountInfo, new_size: usize) -> Result<(), ProgramError> {
    // Missing: no signer check
    // Missing: no rent/lamport check
    account.realloc(new_size, false)?;
    Ok(())
}

pub fn expand_data(account: &AccountInfo, payer: &AccountInfo, new_size: usize) -> Result<(), ProgramError> {
    // Has rent check but missing signer check
    let rent = solana_program::sysvar::rent::Rent::get()?;
    let _min = rent.minimum_balance(new_size);
    account.realloc(new_size, false)?;
    Ok(())
}
