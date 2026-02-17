// SOL-012: Token-2022 Extension Safety
// This program accepts Token-2022 tokens without checking for dangerous extensions.
// A malicious mint with PermanentDelegate could drain user tokens after deposit.

fn process_deposit(
    mint: &InterfaceAccount<Mint>,
    from: &InterfaceAccount<TokenAccount>,
    to: &InterfaceAccount<TokenAccount>,
    authority: &Signer,
    token_program: &Interface<TokenInterface>,
) {
    // VULNERABLE: No check for PermanentDelegate, TransferHook, or MintCloseAuthority extensions
    let cpi_ctx = CpiContext::new(
        token_program.to_account_info(),
        TransferChecked {
            from: from.to_account_info(),
            to: to.to_account_info(),
            authority: authority.to_account_info(),
            mint: mint.to_account_info(),
        },
    );
    transfer_checked(cpi_ctx, amount, mint.decimals)?;
}

fn process_withdrawal(
    mint: &InterfaceAccount<Mint>,
    vault: &InterfaceAccount<TokenAccount>,
    user_ata: &InterfaceAccount<TokenAccount>,
    vault_authority: &AccountInfo,
    token_program: &Interface<TokenInterface>,
) {
    // VULNERABLE: Accepts any Token-2022 mint without extension validation
    let seeds = &[b"vault", &[bump]];
    let signer_seeds = &[&seeds[..]];
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        TransferChecked {
            from: vault.to_account_info(),
            to: user_ata.to_account_info(),
            authority: vault_authority.to_account_info(),
            mint: mint.to_account_info(),
        },
        signer_seeds,
    );
    transfer_checked(cpi_ctx, withdraw_amount, mint.decimals)?;
}
