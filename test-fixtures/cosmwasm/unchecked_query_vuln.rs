// Test fixture for CW-005: unchecked-query-response
// Querier results used without bounds or validity checks

fn execute_oracle_update(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    let price: PriceResponse = deps.querier.query_wasm_smart(
        oracle_addr,
        &OracleQuery::Price { asset: "uatom".to_string() },
    )?;

    // VULNERABILITY: using queried price without validation
    let value = user_balance * price.rate;
    POSITIONS.save(deps.storage, &info.sender, &value)?;
    Ok(Response::new())
}

fn execute_check_collateral(
    deps: DepsMut,
    env: Env,
) -> StdResult<Response> {
    let result: BalanceResponse = deps.querier.query(
        &QueryRequest::Bank(BankQuery::Balance {
            address: contract_addr.to_string(),
            denom: "uusd".to_string(),
        }),
    )?;

    let total = result.amount.amount;
    CONFIG.save(deps.storage, &Config { collateral: total })?;
    Ok(Response::new())
}
