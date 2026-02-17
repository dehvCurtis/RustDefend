// INK-001: Reentrancy via set_allow_reentry(true)
// Vulnerable: explicitly enables reentrancy, opening the contract to reentrant attacks.

#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod vulnerable_vault {
    use ink::env::call::{build_call, ExecutionInput, Selector};

    #[ink(storage)]
    pub struct Vault {
        balances: ink::storage::Mapping<AccountId, Balance>,
        total_deposits: Balance,
    }

    impl Vault {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                balances: Default::default(),
                total_deposits: 0,
            }
        }

        #[ink(message, payable)]
        pub fn deposit(&mut self) {
            let caller = self.env().caller();
            let amount = self.env().transferred_value();
            let balance = self.balances.get(caller).unwrap_or(0);
            self.balances.insert(caller, &(balance + amount));
            self.total_deposits += amount;
        }

        #[ink(message)]
        pub fn withdraw(&mut self, amount: Balance) {
            let caller = self.env().caller();
            let balance = self.balances.get(caller).unwrap_or(0);
            assert!(balance >= amount, "Insufficient balance");

            // Vulnerable: allows reentrancy — callback before state update
            let call = build_call::<Environment>()
                .call(caller)
                .transferred_value(amount)
                .exec_input(ExecutionInput::new(Selector::new([0x00; 4])))
                .returns::<()>()
                .call_flags(ink::env::CallFlags::default().set_allow_reentry(true))
                .invoke();

            // State update after external call — classic reentrancy
            self.balances.insert(caller, &(balance - amount));
            self.total_deposits -= amount;
        }
    }
}
