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
    //let indexer = city_indexer::Indexer::new(args).await?;
    //indexer.listen().await?;
    city_rollup_core_orchestrator::debug::run_debug_demo_client(args);

    Ok(())
}
