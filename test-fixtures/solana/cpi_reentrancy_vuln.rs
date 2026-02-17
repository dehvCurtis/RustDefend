// Test fixture for SOL-009: cpi-reentrancy
// State mutations after CPI calls (CEI violation)

use solana_program::account_info::AccountInfo;
use solana_program::program::invoke;

fn process_swap(accounts: &[AccountInfo], amount: u64) {
    let swap_ix = solana_program::instruction::Instruction {
        program_id: *accounts[2].key,
        accounts: vec![],
        data: vec![],
    };
    invoke(&swap_ix, accounts).unwrap();

    // VULNERABILITY: state mutation AFTER CPI call
    let mut data = accounts[0].try_borrow_mut_data().unwrap();
    data[0..8].copy_from_slice(&amount.to_le_bytes());
}

fn process_liquidate(accounts: &[AccountInfo]) {
    let cpi_ctx = CpiContext::new(accounts[3].clone(), Transfer {
        from: accounts[0].clone(),
        to: accounts[1].clone(),
    });

    // VULNERABILITY: borrow_mut after CPI
    let mut lamports = accounts[0].try_borrow_mut_lamports().unwrap();
    *lamports = 0;
}
