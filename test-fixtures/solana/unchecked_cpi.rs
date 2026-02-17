// SOL-008: Unchecked CPI return value
// Vulnerable: CPI results are discarded without error handling.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::invoke,
    program::invoke_signed,
    pubkey::Pubkey,
    instruction::Instruction,
};

/// Transfers tokens but discards the CPI result with a wildcard binding.
pub fn transfer_tokens_discard(
    accounts: &[AccountInfo],
    instruction: Instruction,
) -> ProgramResult {
    // Vulnerable: CPI result silently discarded
    let _ = invoke(&instruction, accounts);

    Ok(())
}

/// Transfers tokens via signed CPI but discards the result.
pub fn transfer_tokens_signed_discard(
    accounts: &[AccountInfo],
    instruction: Instruction,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    // Vulnerable: signed CPI result silently discarded
    let _ = invoke_signed(&instruction, accounts, &[signer_seeds]);

    Ok(())
}
