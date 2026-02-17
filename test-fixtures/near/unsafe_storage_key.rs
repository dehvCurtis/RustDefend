// NEAR-009: Unsafe storage keys constructed from user input
// Vulnerable: format!() used to build storage keys with storage_read/storage_write.

use near_sdk::env;

/// Stores user data using a key derived from user input via format!().
/// Predictable keys risk collision attacks.
fn register_user(username: String, data: Vec<u8>) {
    // Vulnerable: user-controlled input in format!() key for storage_write
    let key = format!("user_{}", username);
    env::storage_write(key.as_bytes(), &data);
}

/// Reads user data using a key derived from user input via format!().
fn get_user_data(username: String) -> Option<Vec<u8>> {
    // Vulnerable: user-controlled input in format!() key for storage_read
    let key = format!("user_{}", username);
    env::storage_read(key.as_bytes())
}
