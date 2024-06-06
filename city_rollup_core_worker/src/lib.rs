pub mod actors;

use std::time::Duration;

use city_common::cli::args::L2WorkerArgs;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::root::CRWorkerToolboxRootCircuits;
use city_rollup_common::config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::actors::simple::SimpleActorWorker;
use crate::event_processor::CityEventProcessor;

use crossterm::{
    event::{poll, read, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode},
};
pub mod event_processor;

pub const PROVING_INTERVAL: u64 = 30000;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
pub fn run_debug_outer(args: L2WorkerArgs) -> anyhow::Result<()> {
    let network_magic = get_network_magic_for_str(args.network.to_string())?;
    let toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);
    println!(
        "CRWorkerToolboxCoreCircuitFingerprints: {}",
        serde_json::to_string(&toolbox.core.fingerprints).unwrap()
    );

    if args.worker_mode.is_groth16_enabled() {
        gnark_plonky2_wrapper::initialize(&format!(
            "{}/.city-rollup/keystore/",
            home::home_dir().unwrap().display()
        ))?;
    }
    println!("worker ready");
    loop {
        run_debug_inner(&args, &toolbox)?;
        println!("press enter to reset worker");
        enable_raw_mode()?;
        loop {
            if poll(Duration::from_millis(1_000))? {
                let event = read()?;

                if event == Event::Key(KeyCode::Enter.into()) {
                    break;
                }
            }
        }
        disable_raw_mode()?;
        println!("worker reset!");
    }
}
pub fn run_debug_inner(
    args: &L2WorkerArgs,
    toolbox: &CRWorkerToolboxRootCircuits<C, D>,
) -> anyhow::Result<()> {
    let job_queue = RedisQueue::new(&args.redis_uri)?;
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let mut event_processor = CityEventProcessor::new(job_queue.clone());

    loop {
        'inner: loop {
            if event_processor.job_queue.is_empty() {
                break 'inner;
            }
            SimpleActorWorker::process_next_job(
                &mut proof_store,
                &mut event_processor,
                toolbox,
                args.worker_mode,
            )?;
        }
        enable_raw_mode()?;
        if poll(Duration::from_millis(1_000))? {
            let event = read()?;
            if event == Event::Key(KeyCode::Esc.into()) {
                break;
            }
        }
        disable_raw_mode()?;

        std::thread::sleep(Duration::from_millis(500))
    }

    disable_raw_mode()?;
    Ok(())
}
pub fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    if args.debug_mode == 1 {
        return run_debug_outer(args);
    }
    let job_queue = RedisQueue::new(&args.redis_uri)?;
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let network_magic = get_network_magic_for_str(args.network.to_string())?;
    let mut event_processor = CityEventProcessor::new(job_queue.clone());

    let toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);
/* 
    if args.worker_mode.is_groth16_enabled() {
        gnark_plonky2_wrapper::initialize(&format!(
            "{}/.city-rollup/keystore/",
            home::home_dir().unwrap().display()
        ))?;
    }

    */

    

    tracing::info!(
        "CRWorkerToolboxCoreCircuitFingerprints: {}",
        serde_json::to_string(&toolbox.core.fingerprints).unwrap()
    );

    loop {
        'inner: loop {
            if event_processor.job_queue.is_empty() {
                break 'inner;
            }
            SimpleActorWorker::process_next_job(
                &mut proof_store,
                &mut event_processor,
                &toolbox,
                args.worker_mode,
            )?;
        }

        std::thread::sleep(Duration::from_secs(1))
    }
}
