// Test fixture for INK-008: ink-result-suppression
// let _ = expr where expr returns Result

impl MyContract {
    #[ink(message)]
    pub fn process_payment(&mut self, recipient: AccountId, amount: Balance) {
        let _ = self.env().transfer(recipient, amount);
        self.payments_processed += 1;
    }

    #[ink(message)]
    pub fn save_state(&mut self) {
        let _ = self.try_save_checkpoint();
        self.checkpoint_count += 1;
    }

    fn try_save_checkpoint(&self) -> Result<(), Error> {
        Ok(())
    }
}
