pub mod actors;
use std::sync::Arc;
use std::time::Duration;

use city_common::cli::args::L2WorkerArgs;
use city_macros::sync_infinite_loop;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::prover::QWorkerStandardProver;
use city_rollup_circuit::worker::toolbox::root::CRWorkerToolboxRootCircuits;
use city_rollup_common::config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::implementations::redis::Q_JOB;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use city_store::config::C;
use city_store::config::D;

pub mod event_processor;

pub const PROVING_INTERVAL: u64 = 30000;

pub fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    let redis_dispatcher = RedisDispatcher::new(&args.redis_uri)?;
    let proof_store = RedisStore::new(&args.redis_uri)?;
    let network_magic = get_network_magic_for_str(args.network.to_string())?;

    let qworker = QWorkerStandardProver::new();

    let toolbox = Arc::new(CRWorkerToolboxRootCircuits::<C, D>::new(
        network_magic,
        SIGHASH_WHITELIST_TREE_ROOT,
    ));

    sync_infinite_loop!(PROVING_INTERVAL, {
        let mut proof_store = proof_store.clone();
        let mut redis_dispatcher = redis_dispatcher.clone();
        let mut qworker = qworker.clone();
        if let Some((id, message)) = redis_dispatcher
            .receive_one(Q_JOB, Some(Duration::from_millis(PROVING_INTERVAL)))?
        {
            let job_id: QProvingJobDataID = serde_json::from_slice(&message)?;
            qworker.prove(&mut proof_store, &*toolbox, job_id)?;
            redis_dispatcher.delete_message(Q_JOB, id)?;
        }
    });
}
