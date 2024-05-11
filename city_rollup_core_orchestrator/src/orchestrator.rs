use std::sync::Arc;
use std::time::Duration;

use city_common::cli::args::OrchestratorArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_macros::async_infinite_loop;
use city_macros::define_table;
use city_macros::spawn_async_infinite_loop;
use city_redis_store::ChainState;
use city_redis_store::RedisStore;
use city_redis_store::LAST_ORCHESTOR_BLOCK_ID;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::api::data::block::requested_actions::CityAddDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityProcessWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityRequest;
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
use city_rollup_common::qworker::redis_proof_store::SyncRedisProofStore;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::implementations::redis::Q_TX;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use city_store::config::C;
use city_store::config::D;
use city_store::config::F;
use city_store::config::L2_BLOCK_STATE_TABLE_TYPE;
use city_store::models::l2_block_state::data::L2BlockStateKeyCore;
use city_store::models::l2_block_state::model::L2BlockStatesModel;
use city_store::models::l2_block_state::model::L2BlockStatesModelCore;
use kvq::adapters::standard::KVQStandardAdapter;
use kvq_store_redb::KVQReDBStore;
use plonky2::hash::hash_types::RichField;
use redb::Database;
use redb::Table;
use redb::TableDefinition;

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;
pub const SEQUENCING_TICK: u64 = 100;
pub const BLOCK_BUILDING_INTERVAL: u64 = 1000;

pub const MAX_WITHDRAWALS_PROCESSED_PER_BLOCK: u64 = 10;

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
    pub store: RedisStore,
    pub proof_store: SyncRedisProofStore,
    pub db: Arc<Database>,
    pub dispatcher: RedisDispatcher,
    pub toolbox: Arc<CRWorkerToolboxCoreCircuits<C, D>>,
    pub link_api: BTCLinkAPI,
}

impl Orchestrator {
    pub async fn new(args: OrchestratorArgs) -> anyhow::Result<Self> {
        let store = RedisStore::new(&args.redis_uri).await?;
        let proof_store = SyncRedisProofStore::new(&args.redis_uri)?;
        let dispatcher = RedisDispatcher::new_with_pool(store.get_pool())?;
        let db = Arc::new(Database::create(args.db_path)?);
        let link_api = BTCLinkAPI::new(args.bitcoin_rpc, args.electrs_api);
        let toolbox = Arc::new(CRWorkerToolboxCoreCircuits::new(get_network_magic_for_str(
            args.network.to_string(),
        )?));

        let orchestrator = Self {
            store,
            proof_store,
            db,
            dispatcher,
            toolbox,
            link_api,
        };

        orchestrator.sequence_block();

        Ok(orchestrator)
    }

    pub fn sequence_block(&self) {
        let redis_store = self.store.clone();

        spawn_async_infinite_loop!(SEQUENCING_TICK, {
            redis_store.try_sequence_block().await?;
        });
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

        let chain_state = self.store.get_block_state().await?;

        // keep us to be 2 blocks before the latest block to ensure the queue is filled
        // with all block transactions
        if chain_state.last_orchestrator_block_id + 2 >= chain_state.last_block_id {
            println!("wait new blocks");
            return Ok(());
        }

        println!(
            "block height: {}, current building block: {}",
            chain_state.last_block_id, chain_state.last_orchestrator_block_id
        );

        let messages = self.get_all_txs(&chain_state).await?;

        let mut store = KVQReDBStore::new(wxn.open_table(KV)?);

        let job_ids = self.process_txs(messages, &mut store, chain_state).await?;

        let dummy_state_root = QHashOut::ZERO;
        self.generate_agg_jobs(job_ids, chain_state, dummy_state_root)?;

        let new_chain_state = self.store.get_block_state().await?;

        L2BlockStateModel::set_block_state(
            &mut store,
            CityL2BlockState {
                checkpoint_id: chain_state.last_orchestrator_block_id,
                next_add_withdrawal_id: new_chain_state.add_withdrawal_counter,
                next_process_withdrawal_id: new_chain_state.processed_withdrawal_counter,
                next_deposit_id: new_chain_state.add_deposit_counter,
                total_deposits_claimed_epoch: new_chain_state.claim_l1_deposit_counter,
                next_user_id: new_chain_state.user_counter,
                end_balance: 0,
            },
        )?;

        std::mem::drop(store);

        self.store
            .incr_block_state_counter(LAST_ORCHESTOR_BLOCK_ID)
            .await?;

        wxn.commit()?;
        Ok(())
    }

    async fn get_all_txs(
        &mut self,
        chain_state: &ChainState,
    ) -> Result<Vec<(Option<String>, CityRequest<F>)>, anyhow::Error> {
        let mut messages = self
            .dispatcher
            .receive_all::<Q_TX>(chain_state.last_orchestrator_block_id)
            .await?
            .into_iter()
            .flat_map(|(id, message)| {
                Some((
                    Some(id),
                    serde_json::from_slice::<CityRequest<F>>(&message).ok()?,
                ))
            })
            .collect::<Vec<_>>();
        let next_block_redeem_script = self.store.get_next_block_redeem_script().await?;
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
        messages.extend(funding_transactions.iter().map(|tx| {
            (
                None,
                CityRequest::CityAddDepositRequest((
                    0,
                    CityAddDepositRequest::new_from_transaction(tx),
                )),
            )
        }));
        let pending_withdrawals = (chain_state.add_withdrawal_counter
            - chain_state.processed_withdrawal_counter
            + messages
                .iter()
                .filter(|(_, x)| matches!(x, &CityRequest::CityAddWithdrawalRequest(_)))
                .count() as u64)
            .min(MAX_WITHDRAWALS_PROCESSED_PER_BLOCK);
        messages.extend((0..pending_withdrawals).map(|i| {
            (
                None,
                CityRequest::CityProcessWithdrawalRequest((
                    0,
                    CityProcessWithdrawalRequest::new(i + chain_state.processed_withdrawal_counter),
                )),
            )
        }));
        Ok(messages)
    }
}
