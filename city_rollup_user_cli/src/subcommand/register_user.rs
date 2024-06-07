use city_common::cli::user_args::RegisterUserArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::api::data::block::rpc_request::CityRegisterUserRPCRequest;
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use std::str::FromStr;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

pub async fn run(args: RegisterUserArgs) -> anyhow::Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);



    let private_key = if args.private_key.eq("random") {
        QHashOut::<GoldilocksField>::rand()
    }else{
        QHashOut::<GoldilocksField>::from_str(&args.private_key)
            .map_err(|e| anyhow::format_err!("{}", e.to_string()))?
    };
    let mut wallet = DebugScenarioWallet::<C, D>::new_fast_setup();

    let l2_public_key = wallet.add_zk_private_key(private_key);
    println!("{{\"public_key\": \"{}\"}}", l2_public_key.to_string());
    let city_register_user_rpcrequest = CityRegisterUserRPCRequest { public_key: l2_public_key };

    provider
        .register_user(city_register_user_rpcrequest)
        .await?;

    Ok(())
}
