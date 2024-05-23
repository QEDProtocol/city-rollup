use city_common::cli::user_args::L1DepositArgs;
use city_crypto::{
    hash::base_types::{hash160::Hash160, hash256::Hash256},
    signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_common::{
    api::data::store::CityL2BlockState,
    link::{data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync},
};
use city_rollup_core_node::rpc::{
    ExternalRequestParams, Id, ResponseResult, RpcParams, RpcRequest, RpcResponse, Version,
};
use serde_json::json;

use anyhow::Result;

pub async fn run(args: L1DepositArgs) -> Result<()> {
    let client = reqwest::Client::new();
    let mut wallet = MemorySecp256K1Wallet::new();
    let api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let from = BTCAddress160::from_p2pkh_key(
        wallet.add_private_key(Hash256::from_hex_string(&args.private_key)?)?,
    );

    let response = client
        .post(&args.rpc_address)
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: ExternalRequestParams {
                method: String::from("cr_getLatestBlockState"),
                params: RpcParams(json!([])),
            },
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<CityL2BlockState>>()
        .await?;

    let checkpoint_id = if let ResponseResult::Success(s) = response.result {
        s.checkpoint_id
    } else {
        return Err(anyhow::format_err!("failed to get latest block state"));
    };

    let deposit_address = client
        .post(&args.rpc_address)
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: ExternalRequestParams {
                method: String::from("cr_getCityBlockDepositAddress"),
                params: RpcParams(json!([checkpoint_id])),
            },
            id: Id::Number(1),
        })
        .send()
        .await?
        .json::<RpcResponse<Hash160>>()
        .await?;

    let deposit_address = if let ResponseResult::Success(s) = deposit_address.result {
        BTCAddress160::new_p2pkh(s)
    } else {
        return Err(anyhow::format_err!("failed to get deposit address"));
    };

    let txid =
        api.fund_address_from_known_p2pkh_address(&wallet, from, deposit_address, args.amount)?;
    api.mine_blocks(10)?;

    println!("txid: {}", txid.to_string());
    Ok(())
}
