use city_common::cli::args::L2DumpProofStoreArgs;


#[tokio::main]
pub async fn run(args: L2DumpProofStoreArgs) -> anyhow::Result<()> {
    city_rollup_core_worker_qbench::dump::run_dump_block_proof_store(&args)?;
    Ok(())
}
