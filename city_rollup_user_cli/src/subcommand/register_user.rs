use city_common::cli::user_args::RegisterUserArgs;
use city_crypto::{hash::{base_types::hash256::Hash256, qhashout::QHashOut}, signature::secp256k1::wallet::CompressedPublicKeyToP2PKH};
use city_rollup_common::{api::data::block::rpc_request::CityRegisterUserRPCRequest, link::data::BTCAddress160};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use std::str::FromStr;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

pub async fn run(args: RegisterUserArgs) -> anyhow::Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);

    let private_key = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let l2_public_key = wallet.add_zk_private_key(private_key);
    let l1_public_key = wallet.add_secp256k1_private_key(Hash256::from_hex_string(&args.private_key)?)?;

    println!("l1 public_key = {}", hex::encode(&l1_public_key.0));
    println!("l1 p2pkh = {}", BTCAddress160::new_p2pkh(l1_public_key.to_p2pkh_address()).to_address_string());
    println!("l2 public_key = {}", l2_public_key.to_string());

    let city_register_user_rpcrequest = CityRegisterUserRPCRequest { public_key: l2_public_key };

    provider
        .register_user(city_register_user_rpcrequest)
        .await?;

    Ok(())
}
