use city_common::cli::user_args::ClaimDepositArgs;
use city_crypto::hash::base_types::hash256::Hash256;
use city_rollup_common::{
    api::data::store::CityL1Deposit, introspection::rollup::constants::get_network_magic_for_str,
};
use city_rollup_core_node::rpc::{
    ExternalRequestParams, Id, RequestParams, ResponseResult, RpcParams, RpcRequest, RpcResponse,
    Version,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

use anyhow::Result;
use serde_json::json;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: ClaimDepositArgs) -> Result<()> {
    let client = reqwest::Client::new();

    let network_magic = get_network_magic_for_str(args.network)?;

    let wallet = DebugScenarioWallet::<C, D>::new();

    let txid = Hash256::from_hex_string(&args.txid)?;

    let response = client
        .post(&args.rpc_address)
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: ExternalRequestParams {
                method: String::from("cr_getDepositByTxid"),
                params: RpcParams(json!([txid])),
            },
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<CityL1Deposit>>()
        .await?;

    let deposit = if let ResponseResult::Success(s) = response.result {
        s
    } else {
        return Err(anyhow::format_err!("failed to get deposit"));
    };

    let city_claim_deposit_request =
        wallet.sign_claim_deposit(network_magic, args.user_id, &deposit)?;

    let response = client /*  */
        .post(&args.rpc_address)
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::<F>::ClaimDeposit(city_claim_deposit_request),
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<serde_json::Value>>()
        .await?;

    match response.result {
        ResponseResult::Success(s) => println!("claim deposit {:?}", s),
        ResponseResult::Error(e) => println!("claim deposit failed {:?}", e.message),
    }

    Ok(())
}
