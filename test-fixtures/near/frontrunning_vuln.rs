// Test fixture for NEAR-008: frontrunning-risk
// Promise::new().transfer() with user-provided parameters

fn execute_payment(&mut self, recipient: AccountId, amount: U128) {
    self.total_paid += amount.0;
    Promise::new(recipient).transfer(amount.0);
}

fn send_reward(&mut self, winner: AccountId, prize: U128) {
    self.rewards_distributed += 1;
    Promise::new(winner).transfer(prize.0);
}
