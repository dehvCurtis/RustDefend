// Test fixture for SOL-010: unsafe-pda-seeds
// PDA derivation with only static seeds (no user-specific components)

use solana_program::pubkey::Pubkey;

fn get_global_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"config"],
        program_id,
    )
}

fn get_vault_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"vault", b"main"],
        program_id,
    )
}
