// NEAR-003: Storage staking auth bypass
// Vulnerable: storage_deposit and storage_withdraw don't check predecessor_account_id.

use near_sdk::{env, json_types::U128, AccountId, Promise};

/// Accepts a storage deposit but doesn't verify who is calling.
fn storage_deposit(account_id: Option<AccountId>) -> StorageBalance {
    // Vulnerable: no predecessor_account_id() check
    // Any cross-contract caller could deposit on behalf of a victim
    let deposit = env::attached_deposit();
    let target = account_id.unwrap_or_else(|| env::signer_account_id());

    internal_storage_deposit(&target, deposit);

    storage_balance_of(target).unwrap()
}

/// Withdraws storage deposit without verifying the caller.
fn storage_withdraw(amount: Option<U128>) -> StorageBalance {
    // Vulnerable: no predecessor_account_id() check
    // Uses signer_account_id which can differ from caller in cross-contract
    let account_id = env::signer_account_id();
    let withdraw_amount = amount.map(|a| a.0).unwrap_or(0);

    internal_storage_withdraw(&account_id, withdraw_amount);

    Promise::new(account_id.clone()).transfer(withdraw_amount);

    storage_balance_of(account_id).unwrap()
}

/// Unregisters storage without proper auth.
fn storage_unregister(force: Option<bool>) -> bool {
    // Vulnerable: no predecessor_account_id() check
    let account_id = env::signer_account_id();
    internal_storage_unregister(account_id, force.unwrap_or(false))
}
