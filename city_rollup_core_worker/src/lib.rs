pub mod actors;

use city_common::cli::args::L2WorkerArgs;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::root::CRWorkerToolboxRootCircuits;
use city_rollup_common::config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::actors::simple::SimpleActorWorker;
use crate::event_processor::CityEventProcessor;

pub mod event_processor;

pub const PROVING_INTERVAL: u64 = 30000;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

pub fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    let dispatcher = RedisDispatcher::new(&args.redis_uri)?;
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let network_magic = get_network_magic_for_str(args.network.to_string())?;
    let mut event_processor = CityEventProcessor::new(dispatcher.clone());

    let toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);

    loop {
        if event_processor.job_queue.is_empty() {
            break;
        }
        SimpleActorWorker::process_next_job(&mut proof_store, &mut event_processor, &toolbox)?;
    }

    Ok::<_, anyhow::Error>(())
}
