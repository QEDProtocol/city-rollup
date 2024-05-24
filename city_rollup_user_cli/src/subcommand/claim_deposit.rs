use std::str::FromStr;

use city_common::cli::user_args::ClaimDepositArgs;
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;

use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

use anyhow::Result;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: ClaimDepositArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);

    let network_magic = get_network_magic_for_str(args.network)?;

    let private_key = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    wallet.add_zk_private_key(private_key);

    let txid = Hash256::from_hex_string(&args.txid)?;

    let deposit = provider.get_deposit_by_txid(txid).await?;

    let city_claim_deposit_request =
        wallet.sign_claim_deposit(network_magic, args.user_id, &deposit)?;

    provider /*  */
        .claim_deposit::<F>(city_claim_deposit_request)
        .await?;

    Ok(())
}