// CW-003: Missing sender check in execute handler
// Vulnerable: storage is mutated without checking info.sender.

use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult};

pub enum ExecuteMsg {
    UpdateConfig { new_admin: String },
    Withdraw { amount: u128 },
}

/// Handles execute messages — no sender validation before storage writes.
pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::UpdateConfig { new_admin } => {
            // Vulnerable: anyone can update the admin — no info.sender check
            CONFIG.save(deps.storage, &Config { admin: new_admin })?;
            Ok(Response::new().add_attribute("action", "update_config"))
        }
        ExecuteMsg::Withdraw { amount } => {
            // Vulnerable: anyone can withdraw — no info.sender check
            BALANCE.update(deps.storage, |bal| -> StdResult<u128> {
                Ok(bal.checked_sub(amount).unwrap_or(0))
            })?;
            Ok(Response::new().add_attribute("action", "withdraw"))
        }
    }
}
