pub mod debug;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Address;
use bitcoin::Network;
use bitcoin::Script;
use city_common::cli::args::OrchestratorArgs;
use city_crypto::hash::base_types::felt252::felt252_hashout_to_hash256_le;
use city_crypto::hash::base_types::hash160::Hash160;
use city_crypto::hash::base_types::hash256::Hash256;
use city_crypto::hash::core::btc::btc_hash160;
use city_macros::define_table;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::api::data::block::rpc_request::CityRPCRequest;
use city_rollup_common::api::data::btc_spend_info::SimpleRollupBTCSpendInfo;
use city_rollup_common::api::data::btc_spend_info::SimpleRollupBlockSpendSigHashHint;
use city_rollup_common::api::data::store::CityL2BlockState;
use city_rollup_common::config::sighash_wrapper_config::SIGHASH_CIRCUIT_MAX_DEPOSITS;
use city_rollup_common::config::sighash_wrapper_config::SIGHASH_CIRCUIT_MAX_WITHDRAWALS;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_common::introspection::sighash::SIGHASH_ALL;
use city_rollup_common::introspection::transaction::BTCTransaction;
use city_rollup_common::introspection::transaction::BTCTransactionInput;
use city_rollup_common::introspection::transaction::BTCTransactionOutput;
use city_rollup_common::link::data::BTCOutpoint;
use city_rollup_common::link::data::BTCUTXO;
use city_rollup_common::link::link_api::BTCLinkAPI;
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
use city_store::models::l2_block_state::model::L2BlockStatesModelReaderCore;
use city_store::store::city::base::CityStore;
use city_store::store::sighash::SigHashMerkleTree;
use kvq::adapters::standard::KVQStandardAdapter;
use kvq::traits::KVQBinaryStore;
use kvq_store_redb::KVQReDBStore;
use redb::Database;
use redb::Table;
use redb::TableDefinition;

use crate::debug::scenario::block_planner::planner::CityOrchestratorBlockPlanner;
use crate::debug::scenario::requested_actions::CityScenarioRequestedActions;
use crate::debug::scenario::rpc_processor::CityScenarioRequestedActionsFromRPC;
use crate::debug::scenario::rpc_processor::DebugRPCProcessor;
use crate::debug::scenario::sighash::finalizer::SigHashFinalizer;

pub const BLOCK_BUILDING_INTERVAL: u64 = 1000;

define_table! { KV, &[u8], &[u8] }

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
    pub network: Network,
}

impl Orchestrator {
    pub async fn new(args: OrchestratorArgs) -> anyhow::Result<Self> {
        let redis_store = RedisStore::new(&args.redis_uri)?;
        let dispatcher = RedisDispatcher::new(&args.redis_uri).await?;
        let db = Arc::new(Database::create(args.db_path)?);
        let link_api = BTCLinkAPI::new(args.bitcoin_rpc, args.electrs_api);
        let network = Network::from_core_arg(&args.network.to_string())?;
        let toolbox = Arc::new(CRWorkerToolboxCoreCircuits::new(get_network_magic_for_str(
            args.network.to_string(),
        )?));

        let orchestrator = Self {
            redis_store,
            db,
            dispatcher,
            toolbox,
            link_api,
            network,
        };

        Ok(orchestrator)
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.build_block().await
    }

    pub async fn build_block(&mut self) -> anyhow::Result<()> {
        let db = self.db.clone();
        let wxn = db.begin_write()?;

        let (block_id, _) = self.redis_store.get_block_state()?;

        println!("current building block: {}", block_id);

        let mut redis_store = self.redis_store.clone();
        let (agg_job_ids, block_end_job_ids, sighash_job_ids) = {
            let mut store = KVQReDBStore::new(wxn.open_table(KV)?);

            let txs = self.get_txs(block_id, &mut redis_store).await?;
            let prev_block_state =
                L2BlockStateModel::get_block_state_by_id(&store, block_id).unwrap_or_default();

            let current_block_redeem_script = self.redis_store.get_current_block_redeem_script()?;
            let last_block_spend_output = self.redis_store.get_last_block_spend_output()?;
            let (funding_utxos, last_block_spend_index) =
                self.get_funding_utxos(&current_block_redeem_script, &last_block_spend_output)?;

            let funding_transactions = self.get_funding_transactions(&funding_utxos)?;
            let requested_actions = CityScenarioRequestedActions::new_from_requested_rpc(
                txs,
                funding_transactions
                    .iter()
                    .skip(if last_block_spend_index != -1 { 1 } else { 0 }),
                &prev_block_state,
                SIGHASH_CIRCUIT_MAX_WITHDRAWALS,
            );

            let mut block_planner = CityOrchestratorBlockPlanner::new(
                self.toolbox.get_fingerprint_config(),
                prev_block_state,
            );

            let (next_block_state, agg_job_ids, _, block_end_job_ids) =
                block_planner.process_requests(&mut store, &mut redis_store, &requested_actions)?;

            let final_state_root = felt252_hashout_to_hash256_le(
                CityStore::get_city_root(&store, next_block_state.checkpoint_id)?.0,
            );
            let next_block_redeem_script =
                self.get_next_block_redeem_script(&current_block_redeem_script, &final_state_root)?;

            CityStore::set_block_state(&mut store, &next_block_state)?;
            self.redis_store
                .set_current_block_redeem_script(&next_block_redeem_script)?;

            let mut accessed_users = requested_actions.accessed_users();
            accessed_users.extend(prev_block_state.next_user_id..next_block_state.next_user_id);
            self.cache_accessed_users(&mut store, block_id, accessed_users)?;

            let inputs = funding_utxos
                .iter()
                .map(|utxo| BTCTransactionInput {
                    hash: utxo.txid,
                    index: utxo.vout,
                    script: current_block_redeem_script.clone(),
                    sequence: 4294967295,
                })
                .collect::<Vec<_>>();
            let mut outputs = requested_actions
                .process_withdrawals
                .iter()
                .map(|req| {
                    let withdrawal =
                        CityStore::get_withdrawal_by_id(&store, block_id, req.withdrawal_id)?;

                    Ok(BTCTransactionOutput {
                        value: withdrawal.value,
                        script: self.get_withdrawal_p2pkh(&withdrawal.address)?, // p2pkh
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if last_block_spend_index != -1 {
                outputs.insert(
                    0,
                    BTCTransactionOutput {
                        value: next_block_state.end_balance,
                        script: self.get_block_p2sh(&next_block_redeem_script)?, // p2sh
                    },
                )
            }
            let input_len = inputs.len();

            let tx = BTCTransaction {
                version: 2,
                locktime: 0,
                inputs,
                outputs,
            };
            self.redis_store.set_last_block_spend_output(BTCOutpoint {
                txid: tx.get_hash(), // TODO: fix this
                vout: 0,
            })?;
            let mut sighash_hints_for_spend_inputs = vec![];
            for input_index in 0..input_len {
                let sighash_preimage = tx.get_sig_hash_preimage(
                    input_index,
                    &current_block_redeem_script,
                    SIGHASH_ALL,
                );

                sighash_hints_for_spend_inputs.push(SimpleRollupBlockSpendSigHashHint {
                    sighash: sighash_preimage.get_hash(),
                    sighash_preimage: sighash_preimage.to_bytes(),
                    index: input_index,
                    txid: tx.inputs[input_index].hash,
                    funding_tx: funding_transactions[input_index].to_bytes(),
                });
            }

            let spend_info = SimpleRollupBTCSpendInfo {
                sighash_hints_for_spend_inputs,
                next_block_redeem_script: next_block_redeem_script,
            };

            let hints = spend_info.to_block_spend_hints()?;

            let sighash_whitelist_tree = SigHashMerkleTree::new();
            let sighash_job_ids = SigHashFinalizer::finalize_sighashes::<RedisStore>(
                &mut self.redis_store,
                sighash_whitelist_tree,
                next_block_state.checkpoint_id,
                *block_end_job_ids.last().unwrap(),
                &hints,
            )?;

            (agg_job_ids, block_end_job_ids, sighash_job_ids)
        };

        for job in agg_job_ids.plan_jobs() {
            self.dispatcher.dispatch(Q_JOB, job).await?;
        }

        for job in block_end_job_ids {
            self.dispatcher.dispatch(Q_JOB, job).await?;
        }

        for job in sighash_job_ids.sighash_final_gl_job_ids {
            self.dispatcher.dispatch(Q_JOB, job).await?;
        }

        for job in sighash_job_ids.wrap_sighash_final_bls12381_job_ids {
            self.dispatcher.dispatch(Q_JOB, job).await?;
        }

        redis_store.sequence_block()?;

        wxn.commit()?;
        Ok(())
    }

    fn cache_accessed_users<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        checkpoint_id: u64,
        accessed_users: HashSet<u64>,
    ) -> anyhow::Result<()> {
        for user_id in accessed_users {
            let user_state = CityStore::<S>::get_user_by_id(store, checkpoint_id, user_id)?;
            self.redis_store.set_user_state(&user_state)?;
        }
        Ok(())
    }

    async fn get_txs(
        &mut self,
        checkpoint_id: u64,
        proof_store: &mut RedisStore,
    ) -> Result<CityScenarioRequestedActionsFromRPC<F>, anyhow::Error> {
        let rpc_processor = DebugRPCProcessor::<F, D>::new(checkpoint_id);
        for (id, message) in self
            .dispatcher
            .receive_all(Q_TX, Some(Duration::from_secs(2)))
            .await?
        {
            match serde_json::from_slice::<CityRPCRequest<F>>(&message)? {
                CityRPCRequest::CityTokenTransferRPCRequest((rpc_node_id, req)) => {
                    rpc_processor.injest_rpc_token_transfer(proof_store, rpc_node_id, &req)?;
                    self.dispatcher.delete_message(Q_TX, id).await?;
                }
                CityRPCRequest::CityRegisterUserRPCRequest((rpc_node_id, req)) => {
                    rpc_processor.injest_rpc_register_user(rpc_node_id, &req)?;
                    self.dispatcher.delete_message(Q_TX, id).await?;
                }
                CityRPCRequest::CityClaimDepositRPCRequest((rpc_node_id, req)) => {
                    rpc_processor.injest_rpc_claim_deposit(proof_store, rpc_node_id, &req)?;
                    self.dispatcher.delete_message(Q_TX, id).await?;
                }
                CityRPCRequest::CityAddWithdrawalRPCRequest((rpc_node_id, req)) => {
                    if rpc_processor.output.add_withdrawals.len() < SIGHASH_CIRCUIT_MAX_WITHDRAWALS
                    {
                        rpc_processor.injest_rpc_add_withdrawal(proof_store, rpc_node_id, &req)?;
                        self.dispatcher.delete_message(Q_TX, id).await?;
                    }
                }
            }
        }

        Ok(rpc_processor.output)
    }

    pub fn get_next_block_redeem_script(
        &self,
        current_block_redeem_script: &[u8],
        next_block_state_hash: &Hash256,
    ) -> anyhow::Result<Vec<u8>> {
        let mut bytes = vec![];
        bytes.copy_from_slice(&current_block_redeem_script[0..1]);
        bytes.copy_from_slice(&next_block_state_hash.0);
        bytes.extend_from_slice(&current_block_redeem_script[33..]);
        Ok(bytes)
    }

    pub fn get_block_p2sh(&self, block_redeem_script: &[u8]) -> anyhow::Result<Vec<u8>> {
        let current_block_redeem_script_hash = btc_hash160(&block_redeem_script);
        let mut bytes = [0; 23];
        bytes.copy_from_slice(&[0xa9, 0x14]);
        bytes.copy_from_slice(&current_block_redeem_script_hash.0);
        bytes.copy_from_slice(&[0x87]);
        Ok(bytes.to_vec())
    }

    pub fn get_withdrawal_p2pkh(&self, address: &Hash160) -> anyhow::Result<Vec<u8>> {
        let mut bytes = [0; 23];
        bytes.copy_from_slice(&[0x76, 0xa9, 0x14]);
        bytes.copy_from_slice(&address.0);
        bytes.copy_from_slice(&[0x88, 0xac]);
        Ok(bytes.to_vec())
    }

    pub fn get_funding_utxos(
        &self,
        current_block_redeem_script: &[u8],
        last_block_spend_output: &Option<BTCOutpoint>,
    ) -> anyhow::Result<(Vec<BTCUTXO>, i32)> {
        let current_block_p2sh = Address::from_script(
            &Script::from_bytes(&self.get_block_p2sh(current_block_redeem_script)?),
            self.network,
        )?
        .to_string();

        let mut utxos = self.link_api.btc_get_utxos(current_block_p2sh)?;
        let mut last_block_spend_index = -1;
        let mut last_block_spend_utxo = None;
        if let Some(last_block_spend_output) = last_block_spend_output {
            if let Some(idx) = utxos.iter().enumerate().find_map(|(idx, utxo)| {
                (utxo.txid == last_block_spend_output.txid
                    && utxo.vout == last_block_spend_output.vout)
                    .then_some(idx)
            }) {
                last_block_spend_utxo = Some(utxos.swap_remove(idx));
            }
        }
        utxos.sort_by_key(|utxo| (utxo.status.block_height, utxo.vout));
        utxos.truncate(SIGHASH_CIRCUIT_MAX_DEPOSITS);
        if let Some(last_block_spend_utxo) = last_block_spend_utxo {
            utxos.insert(0, last_block_spend_utxo);
            last_block_spend_index = 0;
        }
        Ok((utxos, last_block_spend_index))
    }

    pub fn get_tx(&self, txid: Hash256) -> anyhow::Result<BTCTransaction> {
        self.link_api
            .btc_get_raw_transaction(txid)
            .map_err(anyhow::Error::from)
            .and_then(|x| BTCTransaction::from_bytes(&x.0))
    }

    pub fn get_funding_transactions(
        &self,
        utxos: &[BTCUTXO],
    ) -> anyhow::Result<Vec<BTCTransaction>> {
        let funding_transactions = utxos
            .into_iter()
            .map(|utxo| self.get_tx(utxo.txid))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(funding_transactions)
    }
}
