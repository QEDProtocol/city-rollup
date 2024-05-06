use city_common::cli::args::L2WorkerArgs;

use crate::build;
use crate::error::Result;

pub async fn run(args: L2WorkerArgs) -> Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );

    city_rollup_core_worker::worker::run(args).await?;
    Ok(())
}
