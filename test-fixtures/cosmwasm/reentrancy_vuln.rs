// Test fixture for CW-002: cosmwasm-reentrancy
// Storage writes followed by add_message() in IBC/reply context (CEI violation)
// CosmWasm is non-reentrant by design, but IBC hooks and reply handlers can be exploited

fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
    amount: Uint128,
) -> StdResult<Response> {
    // State update BEFORE external call in IBC handler
    let new_balance = old_balance + amount;
    BALANCES.save(deps.storage, &msg.packet.dest.channel_id, &new_balance)?;

    let transfer_msg = WasmMsg::Execute {
        contract_addr: recipient.clone(),
        msg: to_binary(&TransferMsg { amount })?,
        funds: vec![],
    };

    Ok(Response::new()
        .add_message(transfer_msg)
        .add_attribute("action", "ibc_receive"))
}

fn reply_handler(
    deps: DepsMut,
    env: Env,
    msg: Reply,
) -> StdResult<Response> {
    // State update in reply before dispatching another SubMsg
    STATE.save(deps.storage, &new_state)?;

    let followup = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: pool,
        msg: to_binary(&SwapMsg {})?,
        funds: vec![],
    });

    Ok(Response::new().add_submessage(SubMsg::new(followup)))
}
