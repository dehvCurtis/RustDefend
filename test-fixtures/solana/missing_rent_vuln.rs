// Test fixture for SOL-011: missing-rent-exempt
// create_account without Rent::get() or minimum_balance check

use solana_program::system_instruction;

fn initialize_account(payer: &Pubkey, new_account: &Pubkey, space: u64) {
    let ix = system_instruction::create_account(
        payer,
        new_account,
        1_000_000,
        space,
        &program_id,
    );
    invoke(&ix, &[payer_info.clone(), new_account_info.clone()]).unwrap();
}

fn create_data_account(payer: &Pubkey, data_account: &Pubkey) {
    let create_ix = CreateAccount {
        from_pubkey: payer,
        to_pubkey: data_account,
        lamports: 500_000,
        space: 128,
        owner: &program_id,
    };
    invoke(&create_ix.build(), accounts).unwrap();
}
