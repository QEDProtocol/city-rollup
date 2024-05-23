use std::str::FromStr;

use anyhow::Result;

use city_common::cli::user_args::TokenTransferArgs;
use city_crypto::hash::qhashout::QHashOut;

use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_core_node::rpc::{
    Id, RequestParams, ResponseResult, RpcRequest, RpcResponse, Version,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: TokenTransferArgs) -> Result<()> {
    let client = reqwest::Client::new();

    let public_key = QHashOut::<GoldilocksField>::from_str(&args.public_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let network_magic = get_network_magic_for_str(args.network)?;

    let wallet = DebugScenarioWallet::<C, D>::new();

    let city_token_transfer_rpcrequest = wallet.sign_l2_transfer(
        public_key,
        network_magic,
        args.from,
        args.to,
        args.value,
        args.nonce,
    )?;

    let response = client
        .post(&args.rpc_address)
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
