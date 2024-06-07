use city_common::cli::{message::CITY_ROLLUP_BANNER, args::OrchestratorArgs};


pub fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    println!(
        "{}",
        CITY_ROLLUP_BANNER
    );
    city_rollup_core_orchestrator::run(args)?;
    Ok(())
}
