use city_common::cli::args::QBenchArgs;


#[tokio::main]
pub async fn run(args: QBenchArgs) -> anyhow::Result<()> {
    city_rollup_core_worker_qbench::qbench::run_qbench(&args)?;
    Ok(())
}
