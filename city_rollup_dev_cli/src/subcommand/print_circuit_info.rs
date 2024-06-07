use crate::build;
use crate::error::Result;
use city_common::cli::dev_args::PrintCircuitInfoArgs;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

pub async fn run(args: PrintCircuitInfoArgs) -> Result<()> {
    tracing::info!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    let network_magic = get_network_magic_for_str(args.network)?;
    let toolbox_circuits = CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);
    toolbox_circuits.print_op_common_data();

    Ok(())
}
