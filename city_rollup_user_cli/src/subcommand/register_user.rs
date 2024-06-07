use city_common::cli::user_args::RegisterUserArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::api::data::block::rpc_request::CityRegisterUserRPCRequest;
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn parse_multi_hash_string(hash_str: &str) -> anyhow::Result<Vec<QHashOut<GoldilocksField>>> {
    if hash_str.eq("random"){
        let priv_key = QHashOut::rand();
        println!("random_private_key: {}", priv_key.to_string());
        Ok(vec![priv_key])
    }else{
        hash_str
            .split(",")
            .into_iter()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| QHashOut::from_str(x).map_err(|err| err.into()))
            .collect::<anyhow::Result<Vec<QHashOut<GoldilocksField>>>>()
    }
}

fn l2_private_keys_to_public_keys(
    private_keys: &[QHashOut<GoldilocksField>],
) -> anyhow::Result<Vec<QHashOut<GoldilocksField>>> {
    let mut wallet = DebugScenarioWallet::<C, D>::new_fast_setup();
    Ok(private_keys
        .iter()
        .map(|private_key| wallet.add_zk_private_key(*private_key))
        .collect::<Vec<_>>())
}

async fn register_users_with_public_keys(
    provider: &RpcProvider,
    l2_public_keys: &[QHashOut<GoldilocksField>],
) -> anyhow::Result<()> {
    for public_key in l2_public_keys.iter() {
        provider
            .register_user(CityRegisterUserRPCRequest {
                public_key: *public_key,
            })
            .await?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
struct PublicKeysOutput {
    pub public_keys: Vec<QHashOut<GoldilocksField>>,
}

pub async fn run(args: RegisterUserArgs) -> anyhow::Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);
    if !args.private_key.is_empty() && !args.public_key.is_empty() {
        anyhow::bail!("you must provide either --private-key or --public-key, not both");
    }else if args.private_key.is_empty() && args.public_key.is_empty()  {
        anyhow::bail!("you must provide either --private-key or --public-key");
    }

    let public_keys = if args.private_key.is_empty() {
        parse_multi_hash_string(&args.public_key)?
    }else{
        l2_private_keys_to_public_keys(&parse_multi_hash_string(&args.private_key)?)?
    };

    register_users_with_public_keys(&provider, &public_keys).await?;

    let result = PublicKeysOutput {
        public_keys,
    };
    println!("{}",serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}
