// INK-009: Unsafe delegate call with user-controlled code hash
// Vulnerable: delegate_call target is a parameter, not verified against a whitelist.

#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod vulnerable_proxy {
    use ink::env::{
        call::{build_call, DelegateCall, ExecutionInput, Selector},
        DefaultEnvironment,
    };

    #[ink(storage)]
    pub struct Proxy {
        admin: AccountId,
    }

    impl Proxy {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                admin: Self::env().caller(),
            }
        }

        /// Delegates execution to an arbitrary code hash provided by the caller.
        /// Vulnerable: no verification that code_hash is trusted.
        #[ink(message)]
        pub fn forward(
            &self,
            code_hash: Hash,
            selector: [u8; 4],
            input: Vec<u8>,
        ) -> Vec<u8> {
            // Vulnerable: delegate call with user-supplied Hash, no whitelist
            build_call::<DefaultEnvironment>()
                .delegate(code_hash)
                .exec_input(ExecutionInput::new(Selector::new(selector)))
                .returns::<Vec<u8>>()
                .invoke()
        }

        /// Upgrades the contract to an arbitrary code hash.
        /// Vulnerable: target is a parameter without verification.
        #[ink(message)]
        pub fn upgrade(&mut self, target: Hash) {
            // Vulnerable: delegate call with user-supplied target
            build_call::<DefaultEnvironment>()
                .delegate(target)
                .exec_input(ExecutionInput::new(Selector::new([0xDE, 0xAD, 0xBE, 0xEF])))
                .returns::<()>()
                .invoke();
        }
    }
}
