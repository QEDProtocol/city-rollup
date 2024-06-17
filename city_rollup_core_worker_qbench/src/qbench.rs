use crate::dump::BlockProofStoreDump;
use city_common::cli::{args::QBenchArgs, modes::QWorkerMode};
use city_rollup_circuit::worker::toolbox::root::CRWorkerToolboxRootCircuits;
use city_rollup_common::{
    actors::{simple::events::CityEventProcessorMemory, traits::WorkerEventTransmitterSync},
    config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT,
    introspection::rollup::constants::get_network_magic_for_str,
    qworker::job_id::QWorkerJobBenchmark,
};
use city_rollup_core_orchestrator::debug::scenario::actors::job_planner::plan_jobs;
use city_rollup_core_orchestrator::debug::scenario::block_planner::transition::CityOpJobIds;
use city_rollup_core_worker::actors::simple::SimpleActorWorker;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

pub fn run_worker_qbench(
    args: &QBenchArgs,
    dumps: Vec<BlockProofStoreDump>,
) -> anyhow::Result<Vec<QWorkerJobBenchmark>> {
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    println!("Initializing QBench (this may take a few minutes)...");
    let network_magic = get_network_magic_for_str(args.network.to_string())?;

    let mut toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);

    gnark_plonky2_wrapper::initialize(&format!(
        "{}/.city-rollup/keystore/",
        home::home_dir().unwrap().display()
    ))?;
    println!("QBench Initialization Complete!");
    let mut benchmark_results: Vec<QWorkerJobBenchmark> = Vec::new();
    for dump in dumps.into_iter() {
        let dump_config = dump.config.clone();
        let block_op_job_ids =
            CityOpJobIds::dummy_from_config(dump_config.checkpoint_id, &dump_config.job_config);
        let num_input_witnesses = dump_config.job_config.add_deposit_count + 1;

        let mut proof_store = dump.store.clone();
        let mut event_processor = CityEventProcessorMemory::new_with_config(true);

        println!("Running qbench with {} iterations", args.num_iterations);

        for _ in 0..args.num_iterations {
            let leaves = plan_jobs(
                &mut proof_store,
                &block_op_job_ids,
                num_input_witnesses,
                dump_config.checkpoint_id,
            )?;
            event_processor.enqueue_jobs(&leaves)?;
            while !event_processor.job_queue.is_empty() {
                SimpleActorWorker::process_next_job(
                    &mut proof_store,
                    &mut event_processor,
                    &mut toolbox,
                    QWorkerMode::All,
                )?
            }
        }
        benchmark_results.append(&mut event_processor.benchmarks);
    }
    Ok(benchmark_results)
}
pub fn run_qbench(args: &QBenchArgs) -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let input_paths = args
        .input
        .iter()
        .map(|input| root.join(input.clone()).display().to_string())
        .collect::<Vec<_>>();
    let output_path = root.join(args.output.clone()).display().to_string();
    let mut dumps: Vec<BlockProofStoreDump> = Vec::new();
    for input_path in input_paths.iter() {
        let input_bytes = std::fs::read(input_path)?;
        let dump: BlockProofStoreDump = bincode::deserialize(&input_bytes)?;
        dumps.push(dump);
    }
    let results = run_worker_qbench(args, dumps)?;

    let results_json_bytes = serde_json::to_vec_pretty(&results)?;
    std::fs::write(output_path, results_json_bytes)?;

    Ok(())
}
