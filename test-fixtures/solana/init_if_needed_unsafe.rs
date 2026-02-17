// SOL-014: init_if_needed Reinitialization
// This program uses init_if_needed without checking if the account is already initialized.
// An attacker can reinitialize the account to overwrite existing data.

fn initialize_user_profile(ctx: Context<InitUserProfile>) {
    // #[account(init_if_needed, payer = user, space = 8 + UserProfile::LEN)]
    // VULNERABLE: No reinitialization guard
    let profile = &mut ctx.accounts.user_profile;
    profile.init_if_needed;
    profile.authority = ctx.accounts.user.key();
    profile.balance = 0;
    profile.created_at = Clock::get()?.unix_timestamp;
}

fn setup_vault(ctx: Context<SetupVault>) {
    // #[account(init_if_needed, payer = admin, space = 8 + Vault::LEN, seeds = [b"vault"], bump)]
    // VULNERABLE: Attacker can reinitialize vault to reset accumulated funds tracking
    let vault = &mut ctx.accounts.vault;
    vault.init_if_needed;
    vault.admin = ctx.accounts.admin.key();
    vault.total_deposits = 0;
}
