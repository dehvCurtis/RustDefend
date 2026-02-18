// Test fixture: SOL-017 account-data-matching
// Vulnerable: deserializes account data without field validation

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;

pub fn load_pool_state(pool_account: &AccountInfo) -> Result<PoolState, ProgramError> {
    let data = pool_account.try_borrow_data()?;
    let state = PoolState::try_from_slice(&data)?;
    // Missing: no field validation after deserialization
    // Should check state.is_initialized, state.authority == expected, etc.
    Ok(state)
}

pub fn process_swap(source: &AccountInfo, dest: &AccountInfo) -> Result<(), ProgramError> {
    let source_data = source.data.borrow();
    let source_state: TokenAccount = borsh::BorshDeserialize::deserialize(&mut &source_data[..])?;
    // Missing: no validation of source_state fields
    Ok(())
}
