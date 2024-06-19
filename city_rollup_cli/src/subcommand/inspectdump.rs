use city_common::cli::args::InspectL2DumpArgs;


#[tokio::main]
pub async fn run(args: InspectL2DumpArgs) -> anyhow::Result<()> {
    city_rollup_core_worker_qbench::inspect::run_inspect_l2_dump(&args)?;
    Ok(())
}
