// CW-007: Unbounded iteration in execute handler
// Vulnerable: .range() without .take() in execute handlers can exhaust gas.

use cosmwasm_std::{DepsMut, Env, MessageInfo, Order, Response, StdResult};
use cw_storage_plus::Map;

pub const VOTES: Map<&str, u64> = Map::new("votes");

/// Tallies all votes without bounding the iteration.
pub fn execute_tally_votes(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
) -> StdResult<Response> {
    let mut total: u64 = 0;

    // Vulnerable: unbounded .range() — no .take() limit
    for item in VOTES.range(deps.storage, None, None, Order::Ascending) {
        let (_voter, weight) = item?;
        total += weight;
    }

    TALLY.save(deps.storage, &total)?;

    Ok(Response::new()
        .add_attribute("action", "tally")
        .add_attribute("total", total.to_string()))
}

/// Distributes rewards to all stakers without bounding iteration.
pub fn execute_distribute_rewards(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    let mut messages = vec![];

    // Vulnerable: unbounded .range() — no .take() limit
    for item in STAKERS.range(deps.storage, None, None, Order::Ascending) {
        let (addr, stake) = item?;
        let reward = stake * reward_rate;
        messages.push(BankMsg::Send {
            to_address: addr,
            amount: vec![coin(reward, "uatom")],
        });
    }

    Ok(Response::new().add_messages(messages))
}
