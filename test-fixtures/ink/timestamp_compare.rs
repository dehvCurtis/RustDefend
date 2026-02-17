// INK-004: Timestamp dependence in decision logic
// Vulnerable: block_timestamp() used in comparisons and arithmetic.

#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod vulnerable_auction {
    #[ink(storage)]
    pub struct Auction {
        highest_bid: Balance,
        highest_bidder: AccountId,
        end_time: u64,
        owner: AccountId,
    }

    impl Auction {
        #[ink(constructor)]
        pub fn new(duration: u64) -> Self {
            let caller = Self::env().caller();
            Self {
                highest_bid: 0,
                highest_bidder: caller,
                end_time: Self::env().block_timestamp() + duration,
                owner: caller,
            }
        }

        #[ink(message, payable)]
        pub fn bid(&mut self) {
            let now = self.env().block_timestamp();
            // Vulnerable: block_timestamp() in comparison — manipulable by validators
            if now > self.end_time {
                panic!("Auction has ended");
            }

            let bid = self.env().transferred_value();
            assert!(bid > self.highest_bid, "Bid too low");

            self.highest_bid = bid;
            self.highest_bidder = self.env().caller();
        }

        #[ink(message)]
        pub fn finalize(&mut self) {
            // Vulnerable: block_timestamp() used in comparison for authorization
            if self.env().block_timestamp() < self.end_time {
                panic!("Auction still active");
            }

            // Transfer funds to owner
            self.env().transfer(self.owner, self.highest_bid).unwrap();
        }

        #[ink(message)]
        pub fn time_remaining(&self) -> u64 {
            let now = self.env().block_timestamp();
            // Vulnerable: block_timestamp() in arithmetic
            if now < self.end_time {
                self.end_time - self.env().block_timestamp()
            } else {
                0
            }
        }
    }
}
