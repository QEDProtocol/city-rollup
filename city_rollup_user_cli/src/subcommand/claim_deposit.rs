use city_common::cli::user_args::ClaimDepositArgs;
use city_crypto::hash::base_types::hash256::Hash256;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_core_node::rpc::{
    Id, RequestParams, ResponseResult, RpcRequest, RpcResponse, Version,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
};
use std::net::SocketAddr;

use city_store::store::city::base::CityStore;
use kvq::memory::simple::KVQSimpleMemoryBackingStore;

use anyhow::Result;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

type S = KVQSimpleMemoryBackingStore;

pub async fn run(args: ClaimDepositArgs) -> Result<()> {
    let addr: SocketAddr = args.rpc_address.parse()?;
    let client = reqwest::Client::new();

    let network_magic = get_network_magic_for_str(args.network)?;

    let wallet = DebugScenarioWallet::<C, D>::new();

    let store = S::new();

    let txid = Hash256::from_hex_string(&args.txid)?;
    let city_l1_deposit = CityStore::<S>::get_deposit_by_txid(&store, txid)?;

    let city_add_withdrawal_rpcrequest =
        wallet.sign_claim_deposit(network_magic, args.user_id, &city_l1_deposit)?;

    let response = client /*  */
        .post(format!("http://{}", addr))
        .json(&RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::<F>::ClaimDeposit(city_add_withdrawal_rpcrequest),
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
