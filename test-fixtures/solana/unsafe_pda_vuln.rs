// Test fixture for SOL-010: unsafe-pda-seeds
// PDA derivation with only static seeds (no user-specific components)

use solana_program::pubkey::Pubkey;

fn get_escrow_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"escrow"],
        program_id,
    )
}

fn get_reward_pool_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"reward_pool", b"main"],
        program_id,
    )
}
