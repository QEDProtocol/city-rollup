use city_common::cli::args::{OrchestratorArgs, RPCServerArgs};

use crate::build;
use crate::error::Result;

pub async fn run(args: OrchestratorArgs) -> Result<()> {
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
    city_rollup_core_orchestrator::debug::run_debug_demo(args);
    Ok(())
}
