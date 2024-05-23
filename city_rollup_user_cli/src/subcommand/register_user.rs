use city_common::cli::user_args::RegisterUserArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::api::data::block::rpc_request::CityRegisterUserRPCRequest;
use city_rollup_core_node::rpc::{
    Id, RequestParams, ResponseResult, RpcRequest, RpcResponse, Version,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
};
use reqwest;
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Result;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;

pub async fn run(args: RegisterUserArgs) -> Result<()> {
    let addr: SocketAddr = args.rpc_address.parse()?;
    let client = reqwest::Client::new();

    let private_key = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let public_key = wallet.add_zk_private_key(private_key);

    println!("public_key = {}", public_key.to_string());

    let city_register_user_rpcrequest = CityRegisterUserRPCRequest { public_key };

    let response = client
        .post(format!("http://{}", addr))
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

    let network_magic = get_network_magic_for_str("dogetestnet".to_owned())?;

    let city_token_transfer_rpcrequest =
        wallet.sign_l2_transfer(public_key, network_magic, 1, 2, 1, 1)?;

    let response = client
        .post(format!("http://{}", addr))
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::<F>::TokenTransfer(city_token_transfer_rpcrequest),
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<serde_json::Value>>()
        .await?;

    match response.result {
        ResponseResult::Success(s) => println!("transfer token success {:?}", s),
        ResponseResult::Error(e) => println!("transfer token failed {:?}", e.message),
    }

    Ok(())
}
