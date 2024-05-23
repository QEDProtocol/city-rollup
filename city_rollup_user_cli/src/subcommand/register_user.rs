use city_common::cli::user_args::RegisterUserArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::api::data::block::rpc_request::CityRegisterUserRPCRequest;
use city_rollup_core_node::rpc::{
    Id, RequestParams, ResponseResult, RpcRequest, RpcResponse, Version,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use reqwest;
use std::str::FromStr;

use anyhow::Result;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

pub async fn run(args: RegisterUserArgs) -> Result<()> {
    let client = reqwest::Client::new();

    let private_key = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let public_key = wallet.add_zk_private_key(private_key);

    println!("public_key = {}", public_key.to_string());

    let city_register_user_rpcrequest = CityRegisterUserRPCRequest { public_key };

    let response = client
        .post(&args.rpc_address)
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::RegisterUser(city_register_user_rpcrequest),
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<serde_json::Value>>()
        .await?;

    match response.result {
        ResponseResult::Success(s) => println!("register user success {:?}", s),
        ResponseResult::Error(e) => println!("register user failed {:?}", e.message),
    }

    Ok(())
}
