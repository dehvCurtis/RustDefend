// NEAR-007: Self-callback state inconsistency
// Vulnerable: pending state is written before ext_self call without guard checks.

use near_sdk::{env, AccountId, Promise, Gas};

const CALLBACK_GAS: Gas = Gas(5_000_000_000_000);

/// Stakes tokens but writes pending state before the cross-contract call
/// without any guard to prevent double-execution.
fn stake(&mut self, amount: u128) {
    let account_id = env::predecessor_account_id();

    // Vulnerable: writes self.pending state before ext_self call, no guard
    self.pending_stake = amount;
    self.pending_account = account_id.clone();

    // Cross-contract call — callback will finalize the stake
    ext_self::on_stake_complete(
        account_id,
        amount,
        env::current_account_id(),
        0,
        CALLBACK_GAS,
    );
}

/// Unstakes tokens — same vulnerability pattern.
fn unstake(&mut self, amount: u128) {
    let account_id = env::predecessor_account_id();

    // Vulnerable: pending state written without guard
    self.pending_unstake = amount;

    ext_self::on_unstake_complete(
        account_id,
        amount,
        env::current_account_id(),
        0,
        CALLBACK_GAS,
    );
}
