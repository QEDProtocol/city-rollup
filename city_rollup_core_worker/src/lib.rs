pub mod actors;

use std::time::Duration;

use city_common::cli::args::L2WorkerArgs;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::root::CRWorkerToolboxRootCircuits;
use city_rollup_common::{block_template::config::GROTH16_DISABLED_DEV_MODE, config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT};
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
    let mut toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);
    /*println!(
        "CRWorkerToolboxCoreCircuitFingerprints: {}",
        serde_json::to_string(&toolbox.core.fingerprints).unwrap()
    );*/

    if args.worker_mode.is_groth16_enabled() {
        gnark_plonky2_wrapper::initialize(&format!(
            "{}/.city-rollup/keystore/",
            home::home_dir().unwrap().display()
        ))?;
    }
    println!("worker ready");
    loop {
        run_debug_inner(&args, &mut toolbox)?;
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
    toolbox: &mut CRWorkerToolboxRootCircuits<C, D>,
) -> anyhow::Result<()> {
    let job_queue = RedisQueue::new(&args.redis_uri)?;
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let mut event_processor = CityEventProcessor::new_with_config(job_queue.clone(), true);

    let mut should_print_benchmark = false;
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
            if event == Event::Key(KeyCode::Char('p').into()) {
                should_print_benchmark = true;
                break;
            }
        }
        disable_raw_mode()?;

        std::thread::sleep(Duration::from_millis(500))
    }

    disable_raw_mode()?;

    if should_print_benchmark {
        println!("benchmarks: {}", serde_json::to_string(&event_processor.benchmarks)?);
    }
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

    let mut toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);

    //println!("fingerprints:\n{}", serde_json::to_string(&toolbox.core.fingerprints).unwrap());
    if GROTH16_DISABLED_DEV_MODE {
        println!("\x1B[0m\x1B[38;5;227m\x1B[48;5;9m[SECURITY WARNING]\x1B[0m GROTH16_DISABLED_DEV_MODE is set to true, so the rollup will not verify the groth16 proofs on doge (OP_CHECKGROTH16VERIFY is replaced with OP_NOP). GROTH16_DISABLED_DEV_MODE should \x1B[1m\x1B[38;5;9mNEVER\x1B[0m be set to true in production!\x1B[0m");
    }else{
        if args.worker_mode.is_groth16_enabled() {
            gnark_plonky2_wrapper::initialize(&format!(
                "{}/.city-rollup/keystore/",
                home::home_dir().unwrap().display()
            ))?;
        }
    }

    println!("worker setup completed");


    loop {
        'inner: loop {
            if event_processor.job_queue.is_empty() {
                break 'inner;
            }
            SimpleActorWorker::process_next_job(
                &mut proof_store,
                &mut event_processor,
                &mut toolbox,
                args.worker_mode,
            )?;
        }

        std::thread::sleep(Duration::from_secs(1))
    }
}
