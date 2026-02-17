// Test fixture for NEAR-004: callback-unwrap-usage
// #[callback_unwrap] instead of #[callback_result]

#[callback_unwrap]
fn on_transfer_complete(&mut self, amount: U128) {
    self.total_transferred += amount.0;
    log!("Transfer complete: {}", amount.0);
}

#[callback_unwrap]
fn on_stake_complete(&mut self, staked: U128) {
    self.staked_amount = staked.0;
}
