// Test fixture: SOL-020 checked-arithmetic-unwrap
// Vulnerable: uses .checked_add().unwrap() which panics instead of returning error

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;

pub fn calculate_fee(amount: u64, fee_bps: u64) -> u64 {
    let fee = amount.checked_mul(fee_bps).unwrap();
    fee.checked_div(10000).unwrap()
}

pub fn add_rewards(balance: u64, reward: u64) -> u64 {
    balance.checked_add(reward).unwrap()
}
