use anyhow::Result;
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use std::str::FromStr;

use city_common::cli::user_args::AddWithdrawalArgs;
use city_crypto::hash::{base_types::hash160::Hash160, qhashout::QHashOut};
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: AddWithdrawalArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);
    let network_magic = get_network_magic_for_str(args.network)?;

    let private_key = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let public_key = wallet.add_zk_private_key(private_key);

    let destination = Hash160::from_hex_string(&args.destination)?;

    let req = wallet.sign_withdrawal(
        public_key,
        network_magic,
        args.user_id,
        destination,
        args.value,
        args.nonce,
    )?;

    provider.add_withdrawal::<F>(req).await?;

    Ok(())
}
