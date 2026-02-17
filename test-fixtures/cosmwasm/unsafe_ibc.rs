// CW-008: Unsafe IBC Entry Points
// This contract handles IBC packets without channel validation or timeout rollback.

fn ibc_packet_receive(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketReceiveMsg,
) -> StdResult<IbcReceiveResponse> {
    // VULNERABLE: No channel_id validation — accepts packets from any IBC channel
    let packet = msg.packet;
    let data: TransferMsg = from_binary(&packet.data)?;
    let recipient = deps.api.addr_validate(&data.recipient)?;
    BALANCES.update(deps.storage, &recipient, |balance| -> StdResult<Uint128> {
        Ok(balance.unwrap_or_default() + data.amount)
    })?;
    Ok(IbcReceiveResponse::new()
        .add_attribute("action", "receive")
        .add_attribute("amount", data.amount.to_string()))
}

fn ibc_packet_timeout(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketTimeoutMsg,
) -> StdResult<IbcBasicResponse> {
    // VULNERABLE: Empty timeout handler — no rollback of state changes
    // When a packet times out, the sender's funds are lost
    Ok(IbcBasicResponse::new())
}

fn ibc_packet_ack(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketAckMsg,
) -> StdResult<IbcBasicResponse> {
    // VULNERABLE: No channel validation on acknowledgement handler
    let ack: AckResponse = from_binary(&msg.acknowledgement.data)?;
    match ack {
        AckResponse::Result(_) => {},
        AckResponse::Error(err) => {
            PENDING_TRANSFERS.remove(deps.storage, &msg.original_packet.sequence.to_string());
        }
    }
    Ok(IbcBasicResponse::new())
}
