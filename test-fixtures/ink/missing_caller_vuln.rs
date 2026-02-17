// Test fixture for INK-003: ink-missing-caller-check
// #[ink(message)] with &mut self writing storage without caller verification

impl MyContract {
    #[ink(message)]
    pub fn set_owner(&mut self, new_owner: AccountId) {
        self.owner = new_owner;
    }

    #[ink(message)]
    pub fn update_admin(&mut self, admin: AccountId) {
        self.admin = admin;
    }

    #[ink(message)]
    pub fn set_fee(&mut self, fee: u128) {
        self.fee_rate = fee;
    }
}
