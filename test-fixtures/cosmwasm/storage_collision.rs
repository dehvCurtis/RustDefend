// CW-004: Storage prefix collision
// Vulnerable: two different storage containers share the same prefix string.

use cw_storage_plus::{Item, Map};

pub const CONFIG: Item<Config> = Item::new("config");
pub const BALANCES: Map<&str, u128> = Map::new("balances");

// Vulnerable: duplicate prefix "config" — collides with CONFIG above
pub const ADMIN_SETTINGS: Map<&str, String> = Map::new("config");

// Vulnerable: duplicate prefix "balances" — collides with BALANCES above
pub const ALLOWANCES: Map<(&str, &str), u128> = Map::new("balances");

pub struct Config {
    pub admin: String,
    pub fee_rate: u64,
}
