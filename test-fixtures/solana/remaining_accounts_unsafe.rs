// SOL-013: Unsafe remaining_accounts
// This program iterates ctx.remaining_accounts without validating owner, type, or key.
// An attacker can pass arbitrary accounts to manipulate program behavior.

fn process_batch_transfer(ctx: Context<BatchTransfer>) {
    // VULNERABLE: No validation of remaining_accounts
    for account in ctx.remaining_accounts.iter() {
        let data = account.try_borrow_data()?;
        let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
        **account.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
    }
}

fn collect_fees(ctx: Context<CollectFees>) {
    // VULNERABLE: remaining_accounts used without type/owner checks
    let total: u64 = ctx.remaining_accounts.iter().map(|a| {
        let data = a.try_borrow_data().unwrap();
        u64::from_le_bytes(data[8..16].try_into().unwrap())
    }).sum();
    ctx.accounts.fee_collector.amount += total;
}
