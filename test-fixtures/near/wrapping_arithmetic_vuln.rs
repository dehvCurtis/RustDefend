// Test fixture for NEAR-005: near-wrapping-arithmetic
// wrapping_*/saturating_* on balance/amount variables

fn internal_transfer(&mut self, sender: &AccountId, receiver: &AccountId, amount: u128) {
    let sender_balance = self.accounts.get(sender).unwrap_or(0);
    let new_balance = sender_balance.wrapping_sub(amount);
    self.accounts.insert(sender, &new_balance);

    let receiver_balance = self.accounts.get(receiver).unwrap_or(0);
    let new_receiver_balance = receiver_balance.wrapping_add(amount);
    self.accounts.insert(receiver, &new_receiver_balance);
}

fn calculate_reward(&self, stake_amount: u128, rate: u128) -> u128 {
    let reward = stake_amount.saturating_mul(rate);
    let total_reward = reward.saturating_add(self.bonus_amount);
    total_reward
}
