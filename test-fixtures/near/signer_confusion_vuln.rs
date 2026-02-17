// Test fixture for NEAR-002: signer-vs-predecessor
// env::signer_account_id() used in access control

fn withdraw(&mut self, amount: U128) {
    let signer = env::signer_account_id();
    assert_eq!(signer, self.owner, "Only owner can withdraw");
    Promise::new(signer).transfer(amount.0);
}

fn update_config(&mut self, new_fee: u128) {
    let caller = env::signer_account_id();
    require!(caller == self.admin, "Unauthorized");
    self.fee_rate = new_fee;
}
