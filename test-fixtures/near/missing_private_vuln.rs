// Test fixture for NEAR-006: missing-private-callback
// Public methods named on_* without #[private] attribute inside impl block

impl Contract {
    pub fn on_transfer_complete(&mut self, amount: U128) {
        self.total_transferred += amount.0;
        self.pending_transfer = false;
    }

    pub fn on_stake_callback(&mut self, staked: bool) {
        if staked {
            self.staking_active = true;
        }
    }

    pub fn handle_withdrawal(&mut self, success: bool) {
        if success {
            self.withdrawals_count += 1;
        }
    }
}
