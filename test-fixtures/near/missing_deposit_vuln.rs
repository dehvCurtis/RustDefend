// Test fixture for NEAR-010: missing-deposit-check
// #[payable] methods without env::attached_deposit() check inside impl block

impl Contract {
    #[payable]
    pub fn buy_token(&mut self, token_id: TokenId) {
        let buyer = env::predecessor_account_id();
        self.tokens.insert(&token_id, &buyer);
        log!("Token {} purchased by {}", token_id, buyer);
    }

    #[payable]
    pub fn register_account(&mut self) {
        let account_id = env::predecessor_account_id();
        self.registered_accounts.insert(&account_id);
    }
}
