// Test fixture for SOL-001: missing-signer-check
// Functions accepting AccountInfo without verifying is_signer

use solana_program::account_info::AccountInfo;
use solana_program::pubkey::Pubkey;

fn process_withdraw(
    program_id: &Pubkey,
    authority: AccountInfo,
    vault: AccountInfo,
    amount: u64,
) {
    let mut data = vault.try_borrow_mut_data().unwrap();
    data[0..8].copy_from_slice(&amount.to_le_bytes());
}

fn process_update_config(
    program_id: &Pubkey,
    admin: AccountInfo,
    config: AccountInfo,
) {
    let mut data = config.try_borrow_mut_data().unwrap();
    data[0] = 1;
}
