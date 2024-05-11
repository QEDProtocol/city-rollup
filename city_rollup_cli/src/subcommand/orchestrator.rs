use city_common::cli::args::OrchestratorArgs;

use crate::build;
use crate::error::Result;

pub async fn run(args: OrchestratorArgs) -> Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}          |
----------------------------------------
",
        build::PKG_VERSION
    );
    let mut orchestrator =
        city_rollup_core_orchestrator::orchestrator::Orchestrator::new(args).await?;
    orchestrator.run().await?;
    Ok(())
}
