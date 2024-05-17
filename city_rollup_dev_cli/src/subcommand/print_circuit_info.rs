use crate::build;
use crate::error::Result;
use city_common::cli::dev_args::PrintCircuitInfoArgs;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::introspection::rollup::constants::{
    NETWORK_MAGIC_DOGE_MAINNET, NETWORK_MAGIC_DOGE_REGTEST, NETWORK_MAGIC_DOGE_TESTNET,
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

fn get_network_magic_for_str(network: String) -> anyhow::Result<u64> {
    match network.as_str() {
        "dogeregtest" => Ok(NETWORK_MAGIC_DOGE_REGTEST),
        "dogetestnet" => Ok(NETWORK_MAGIC_DOGE_TESTNET),
        "dogemainnet" => Ok(NETWORK_MAGIC_DOGE_MAINNET),
        _ => Err(anyhow::anyhow!("Invalid network {}", network)),
    }
}
pub async fn run(args: PrintCircuitInfoArgs) -> Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );
    //let indexer = city_indexer::Indexer::new(args).await?;
    //indexer.listen().await?;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    let network_magic = get_network_magic_for_str(args.network)?;
    let toolbox_circuits = CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);
    toolbox_circuits.print_op_common_data();

    Ok(())
}
