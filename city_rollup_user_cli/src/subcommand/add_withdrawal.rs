use anyhow::Result;
use std::str::FromStr;

use city_common::cli::user_args::AddWithdrawalArgs;
use city_crypto::hash::{base_types::hash160::Hash160, qhashout::QHashOut};
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_core_node::rpc::{
    Id, RequestParams, ResponseResult, RpcRequest, RpcResponse, Version,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: AddWithdrawalArgs) -> Result<()> {
    let client = reqwest::Client::new();

    let network_magic = get_network_magic_for_str(args.network)?;

    let public_key = QHashOut::<GoldilocksField>::from_str(&args.public_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let wallet = DebugScenarioWallet::<C, D>::new();

    let destination = Hash160::from_hex_string(&args.destination)?;

    let city_add_withdrawal_rpcrequest = wallet.sign_withdrawal(
        public_key,
        network_magic,
        args.user_id,
        destination,
        args.value,
        args.nonce,
    )?;

    let response = client
        .post(&args.rpc_address)
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::<F>::AddWithdrawal(city_add_withdrawal_rpcrequest),
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<serde_json::Value>>()
        .await?;

    match response.result {
        ResponseResult::Success(s) => println!("withdraw success {:?}", s),
        ResponseResult::Error(e) => println!("withdraw failed {:?}", e.message),
    }

    Ok(())
}
