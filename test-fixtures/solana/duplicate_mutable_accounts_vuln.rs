// Test fixture: SOL-019 duplicate-mutable-accounts
// Vulnerable: two AccountInfo params with mutable access but no key uniqueness check

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;

pub fn transfer_tokens(
    from_account: &AccountInfo,
    to_account: &AccountInfo,
    amount: u64,
) -> Result<(), ProgramError> {
    // Missing: no check that from_account.key != to_account.key
    // An attacker could pass the same account for both, causing double-spend
    let mut from_data = from_account.try_borrow_mut_data()?;
    let mut to_data = to_account.try_borrow_mut_data()?;

    let from_balance = u64::from_le_bytes(from_data[..8].try_into().unwrap());
    let to_balance = u64::from_le_bytes(to_data[..8].try_into().unwrap());

    from_data[..8].copy_from_slice(&(from_balance - amount).to_le_bytes());
    to_data[..8].copy_from_slice(&(to_balance + amount).to_le_bytes());

    Ok(())
}
