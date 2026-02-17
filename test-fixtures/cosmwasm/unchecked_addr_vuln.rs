// Test fixture for CW-009: cosmwasm-missing-addr-validation
// Addr::unchecked() usage in non-test code

fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let config = Config {
        admin: Addr::unchecked(&msg.admin),
        treasury: Addr::unchecked(&msg.treasury),
    };
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new())
}

fn execute_update_admin(
    deps: DepsMut,
    info: MessageInfo,
    new_admin: String,
) -> StdResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;
    config.admin = Addr::unchecked(new_admin);
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new())
}
