use std::sync::Arc;
use std::time::Duration;

use city_common::cli::args::OrchestratorArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_macros::async_infinite_loop;
use city_macros::define_table;
use city_macros::spawn_async_infinite_loop;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::api::data::block::requested_actions::CityAddDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityProcessWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityRequest;
use city_rollup_common::api::data::block::rpc_request::CityRPCRequest;
use city_rollup_common::api::data::store::CityL2BlockState;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_common::introspection::transaction::BTCTransaction;
use city_rollup_common::link::link_api::BTCLinkAPI;
use city_rollup_common::qworker::job_witnesses::op::CRAddL1DepositCircuitInput;
use city_rollup_common::qworker::job_witnesses::op::CRAddL1WithdrawalCircuitInput;
use city_rollup_common::qworker::job_witnesses::op::CRClaimL1DepositCircuitInput;
use city_rollup_common::qworker::job_witnesses::op::CRL2TransferCircuitInput;
use city_rollup_common::qworker::job_witnesses::op::CRProcessL1WithdrawalCircuitInput;
use city_rollup_common::qworker::job_witnesses::op::CRUserRegistrationCircuitInput;
use city_rollup_common::qworker::job_witnesses::op::CircuitInputWithJobId;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::implementations::redis::Q_JOB;
use city_rollup_worker_dispatch::implementations::redis::Q_TX;
use city_rollup_worker_dispatch::traits::proving_dispatcher::ProvingDispatcher;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use city_store::config::C;
use city_store::config::D;
use city_store::config::F;
use city_store::config::L2_BLOCK_STATE_TABLE_TYPE;
use city_store::models::l2_block_state::data::L2BlockStateKeyCore;
use city_store::models::l2_block_state::model::L2BlockStatesModel;
use city_store::models::l2_block_state::model::L2BlockStatesModelCore;
use city_store::models::l2_block_state::model::L2BlockStatesModelReaderCore;
use kvq::adapters::standard::KVQStandardAdapter;
use kvq_store_redb::KVQReDBStore;
use plonky2::hash::hash_types::RichField;
use redb::Database;
use redb::Table;
use redb::TableDefinition;

use crate::debug::scenario::block_planner::planner::CityOrchestratorBlockPlanner;
use crate::debug::scenario::process_requests::block_processor::CityOrchestratorBlockProcessor;
use crate::debug::scenario::requested_actions::CityScenarioRequestedActions;
use crate::debug::scenario::rpc_processor::CityScenarioRequestedActionsFromRPC;
use crate::debug::scenario::rpc_processor::DebugRPCProcessor;

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;
pub const SEQUENCING_TICK: u64 = 100;
pub const BLOCK_BUILDING_INTERVAL: u64 = 1000;

pub const MAX_WITHDRAWALS_PROCESSED_PER_BLOCK: usize = 10;

define_table! { KV, &[u8], &[u8] }

#[derive(Default)]
pub struct CityScenarioInputWithJobIds<F: RichField> {
    pub add_deposits: Vec<CircuitInputWithJobId<CRAddL1DepositCircuitInput<F>>>,
    pub add_withdrawals: Vec<CircuitInputWithJobId<CRAddL1WithdrawalCircuitInput<F>>>,
    pub claim_l1_deposits: Vec<CircuitInputWithJobId<CRClaimL1DepositCircuitInput<F>>>,
    pub token_transfers: Vec<CircuitInputWithJobId<CRL2TransferCircuitInput<F>>>,
    pub process_withdrawals: Vec<CircuitInputWithJobId<CRProcessL1WithdrawalCircuitInput<F>>>,
    pub register_users: Vec<CircuitInputWithJobId<CRUserRegistrationCircuitInput<F>>>,
}

pub type L2BlockStateModel<'db, 'txn> = L2BlockStatesModel<
    L2_BLOCK_STATE_TABLE_TYPE,
    KVQReDBStore<Table<'db, 'txn, &'static [u8], &'static [u8]>>,
    KVQStandardAdapter<
        KVQReDBStore<Table<'db, 'txn, &'static [u8], &'static [u8]>>,
        L2BlockStateKeyCore<L2_BLOCK_STATE_TABLE_TYPE>,
        CityL2BlockState,
    >,
>;

#[derive(Clone)]
pub struct Orchestrator {
    pub redis_store: RedisStore,
    pub db: Arc<Database>,
    pub dispatcher: RedisDispatcher,
    pub toolbox: Arc<CRWorkerToolboxCoreCircuits<C, D>>,
    pub link_api: BTCLinkAPI,
}

impl Orchestrator {
    pub async fn new(args: OrchestratorArgs) -> anyhow::Result<Self> {
        let redis_store = RedisStore::new(&args.redis_uri)?;
        let dispatcher = RedisDispatcher::new(&args.redis_uri).await?;
        let db = Arc::new(Database::create(args.db_path)?);
        let link_api = BTCLinkAPI::new(args.bitcoin_rpc, args.electrs_api);
        let toolbox = Arc::new(CRWorkerToolboxCoreCircuits::new(get_network_magic_for_str(
            args.network.to_string(),
        )?));

        let orchestrator = Self {
            redis_store,
            db,
            dispatcher,
            toolbox,
            link_api,
        };

        Ok(orchestrator)
    }

    pub async fn run(self) {
        async_infinite_loop!(BLOCK_BUILDING_INTERVAL, {
            let mut this = self.clone();
            this.build_block().await?;
        })
    }

    pub async fn build_block(&mut self) -> anyhow::Result<()> {
        let db = self.db.clone();
        let wxn = db.begin_write()?;

        let (block_id, _) = self.redis_store.get_block_state()?;

        println!("current building block: {}", block_id);

        let mut redis_store = self.redis_store.clone();
        let (job_ids, _) = {
            let mut store = KVQReDBStore::new(wxn.open_table(KV)?);

            let requested_rpc = self.get_requested_rpc(block_id, &mut redis_store).await?;
            let last_block_state = L2BlockStateModel::get_block_state_by_id(&store, block_id)?;

            let funding_transactions = self.get_funding_transactions()?;
            let requested_actions = CityScenarioRequestedActions::new_from_requested_rpc(
                requested_rpc,
                &funding_transactions,
                &last_block_state,
                MAX_WITHDRAWALS_PROCESSED_PER_BLOCK,
            );

            let mut block_planner = CityOrchestratorBlockPlanner::new(
                self.toolbox.get_fingerprint_config(),
                last_block_state,
            );
            block_planner.process_requests(&mut store, &mut redis_store, &requested_actions)?
        };

        for job in job_ids.plan_jobs() {
            self.dispatcher.dispatch(Q_JOB, job).await?;
        }

        redis_store.sequence_block()?;

        wxn.commit()?;
        Ok(())
    }

    async fn get_requested_rpc(
        &mut self,
        checkpoint_id: u64,
        proof_store: &mut RedisStore,
    ) -> Result<CityScenarioRequestedActionsFromRPC<F>, anyhow::Error> {
        let rpc_processor = DebugRPCProcessor::<F, D>::new(checkpoint_id);
        for (_, message) in self.dispatcher.receive_all(Q_TX).await? {
            match serde_json::from_slice::<CityRPCRequest<F>>(&message)? {
                CityRPCRequest::CityTokenTransferRPCRequest(x) => {
                    rpc_processor.injest_rpc_token_transfer(proof_store, &x.1)?;
                }
                CityRPCRequest::CityRegisterUserRPCRequest(x) => {
                    rpc_processor.injest_rpc_register_user(&x.1)?;
                }
                CityRPCRequest::CityClaimDepositRPCRequest(x) => {
                    rpc_processor.injest_rpc_claim_deposit(proof_store, &x.1)?;
                }
                CityRPCRequest::CityAddWithdrawalRPCRequest(x) => {
                    rpc_processor.injest_rpc_add_withdrawal(proof_store, &x.1)?;
                }
            }
        }

        Ok(rpc_processor.output)
    }

    pub fn get_funding_transactions(&self) -> anyhow::Result<Vec<BTCTransaction>> {
        let next_block_redeem_script = self.redis_store.get_next_block_redeem_script()?;
        let utxos = self.link_api.btc_get_utxos(next_block_redeem_script)?;
        let funding_transactions = utxos
            .into_iter()
            .map(|utxo| {
                self.link_api
                    .btc_get_raw_transaction(utxo.txid)
                    .map_err(anyhow::Error::from)
                    .and_then(|x| BTCTransaction::from_bytes(&x.0))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(funding_transactions)
    }
}
