use city_common::cli::args::OrchestratorArgs;

use crate::build;

pub fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    tracing::info!(
        "
----------------------------------------
|           CityRollup v{}          |
----------------------------------------
",
        build::PKG_VERSION
    );
    city_rollup_core_orchestrator::run(args)?;
    Ok(())
}
