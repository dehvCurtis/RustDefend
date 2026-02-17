// Test fixture for INK-006: ink-cross-contract
// try_invoke() without result checking

impl MyContract {
    #[ink(message)]
    pub fn call_external(&mut self, target: AccountId, value: Balance) {
        let result = ink::env::call::build_call::<Environment>()
            .call(target)
            .transferred_value(value)
            .exec_input(ink::env::call::ExecutionInput::new(
                ink::env::call::Selector::new([0xDE, 0xAD, 0xBE, 0xEF]),
            ))
            .returns::<()>()
            .try_invoke();
        self.calls_made += 1;
    }

    #[ink(message)]
    pub fn delegate_work(&mut self, worker: AccountId) {
        let _discarded = ink::env::call::build_call::<Environment>()
            .call(worker)
            .exec_input(ink::env::call::ExecutionInput::new(
                ink::env::call::Selector::new([0x01, 0x02, 0x03, 0x04]),
            ))
            .returns::<bool>()
            .try_invoke();
    }
}
