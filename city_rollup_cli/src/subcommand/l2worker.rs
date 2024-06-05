use city_common::cli::args::L2WorkerArgs;

use crate::build;

pub fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    tracing::info!(
        "
----------------------------------------
|           CityRollup v{}          |
----------------------------------------
",
        build::PKG_VERSION
    );
    city_rollup_core_worker::run(args)?;
    Ok(())
}
