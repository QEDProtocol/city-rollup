use city_common::cli::args::OrchestratorArgs;

use crate::build;

pub fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );
    city_rollup_core_orchestrator::run(args)?;
    Ok(())
}
