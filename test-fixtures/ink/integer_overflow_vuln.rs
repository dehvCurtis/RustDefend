// Test fixture for INK-002: ink-integer-overflow
// Unchecked arithmetic on Balance/u128 types (standalone functions)

fn transfer_tokens(from_balance: Balance, to_balance: Balance, value: Balance) -> (Balance, Balance) {
    let new_from = from_balance - value;
    let new_to = to_balance + value;
    (new_from, new_to)
}

fn calculate_fee(amount: u128, rate: u128) -> u128 {
    amount * rate
}
