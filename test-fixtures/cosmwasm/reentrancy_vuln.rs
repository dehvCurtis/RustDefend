// Test fixture for CW-002: cosmwasm-reentrancy
// Storage writes followed by add_message() (CEI violation)

fn execute_transfer(
    deps: DepsMut,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> StdResult<Response> {
    // State update BEFORE external call
    BALANCES.save(deps.storage, &info.sender, &(balance - amount))?;

    let msg = WasmMsg::Execute {
        contract_addr: recipient.clone(),
        msg: to_binary(&TransferMsg { amount })?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_message(msg)
        .add_attribute("action", "transfer"))
}

fn execute_swap(
    deps: DepsMut,
    info: MessageInfo,
    pool: String,
) -> StdResult<Response> {
    STATE.save(deps.storage, &new_state)?;

    let swap_msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: pool,
        msg: to_binary(&SwapMsg {})?,
        funds: info.funds,
    });

    Ok(Response::new().add_submessage(SubMsg::new(swap_msg)))
}
