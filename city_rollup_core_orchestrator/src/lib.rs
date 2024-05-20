use city_common::{cli::args::OrchestratorArgs, logging::debug_timer::DebugTimer};
use city_macros::define_table;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::{
    actors::rpc_processor::QRPCProcessor,
    introspection::rollup::constants::get_network_magic_for_str, link::link_api::BTCLinkAPI,
};
use city_rollup_core_worker::event_processor::CityEventProcessor;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq_store_redb::KVQReDBStore;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use redb::{Database, TableDefinition};

use crate::{
    debug::scenario::actors::simple::SimpleActorOrchestrator, event_receiver::CityEventReceiver,
};

pub mod debug;
pub mod event_receiver;

define_table! { KV, &[u8], &[u8] }

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let database = Database::create(&args.db_path)?;
    let queue = RedisQueue::new(&args.redis_uri)?;
    let mut event_processor = CityEventProcessor::new(queue.clone());
    let toolbox = CRWorkerToolboxCoreCircuits::<C, D>::new(get_network_magic_for_str(
        args.network.to_string(),
    )?);
    let mut btc_api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);

    let mut timer = DebugTimer::new("run_orchestrator");
    let sighash_whitelist_tree = SigHashMerkleTree::new();

    loop {
        let wxn = database.begin_write()?;
        {
            let mut store = KVQReDBStore::new(wxn.open_table(KV)?);
            let block_state = CityStore::get_latest_block_state(&store)?;
            let mut event_receiver = CityEventReceiver::<F>::new(
                queue.clone(),
                QRPCProcessor::new(block_state.checkpoint_id),
                proof_store.clone(),
            );
            SimpleActorOrchestrator::run_orchestrator(
                &mut proof_store,
                &mut store,
                &mut event_receiver,
                &mut event_processor,
                &mut btc_api,
                &toolbox.get_fingerprint_config(),
                &sighash_whitelist_tree,
                &mut timer,
            )?;
        }
        wxn.commit()?;
    }
}
