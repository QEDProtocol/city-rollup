use std::str::FromStr;

use anyhow::Result;

use city_common::cli::user_args::TokenTransferArgs;
use city_crypto::hash::qhashout::QHashOut;

use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;

use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: TokenTransferArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);

    let network_magic = get_network_magic_for_str(args.network)?;

    let private_key = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let mut wallet = DebugScenarioWallet::<C, D>::new_fast_setup();

    let public_key = wallet.add_zk_private_key(private_key);

    let city_token_transfer_rpcrequest = wallet.sign_l2_transfer(
        public_key,
        network_magic,
        args.from,
        args.to,
        args.value,
        args.nonce,
    )?;

    provider
        .token_transfer::<F>(city_token_transfer_rpcrequest)
        .await?;

    Ok(())
}
