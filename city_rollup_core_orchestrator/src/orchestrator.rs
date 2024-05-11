use std::sync::Arc;
use std::time::Duration;

use city_common::cli::args::OrchestratorArgs;
use city_macros::async_infinite_loop;
use city_macros::define_table;
use city_macros::spawn_async_infinite_loop;
use city_redis_store::ChainState;
use city_redis_store::RedisStore;
use city_redis_store::DEPOSIT_COUNTER;
use city_redis_store::LAST_ORCHESTOR_BLOCK_ID;
use city_redis_store::TASK_COUNTER;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::api::data::block::requested_actions::CityAddDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityAddWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityClaimDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityProcessWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityRegisterUserRequest;
use city_rollup_common::api::data::block::requested_actions::CityRequest;
use city_rollup_common::api::data::block::requested_actions::CityTokenTransferRequest;
use city_rollup_common::api::data::store::CityL2BlockState;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_common::introspection::rollup::introspection_result::BTCRollupIntrospectionResultDeposit;
use city_rollup_common::introspection::transaction::BTCTransaction;
use city_rollup_common::link::link_api::BTCLinkAPI;
use city_rollup_common::qworker::job_id::ProvingJobCircuitType;
use city_rollup_common::qworker::job_id::ProvingJobDataType;
use city_rollup_common::qworker::job_id::QJobTopic;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
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
use city_store::store::city::base::CityStore;
use kvq::adapters::standard::KVQStandardAdapter;
use kvq::traits::KVQBinaryStore;
use kvq::traits::KVQSerializable;
use kvq_store_redb::KVQReDBStore;
use redb::Database;
use redb::Table;
use redb::TableDefinition;

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;
pub const SEQUENCING_TICK: u64 = 100;
pub const BLOCK_BUILDING_INTERVAL: u64 = 1000;

pub const MAX_WITHDRAWALS_PROCESSED_PER_BLOCK: u64 = 10;

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
    pub store: RedisStore,
    pub db: Arc<Database>,
    pub dispatcher: RedisDispatcher,
    pub toolbox: Arc<CRWorkerToolboxCoreCircuits<C, D>>,
    pub link_api: BTCLinkAPI,
}

impl Orchestrator {
    pub async fn new(args: OrchestratorArgs) -> anyhow::Result<Self> {
        let store = RedisStore::new(&args.redis_uri).await?;
        let dispatcher = RedisDispatcher::new_with_pool(store.get_pool())?;
        let db = Arc::new(Database::create(args.db_path)?);
        let link_api = BTCLinkAPI::new(args.bitcoin_rpc, args.electrs_api);
        let toolbox = Arc::new(CRWorkerToolboxCoreCircuits::new(get_network_magic_for_str(
            args.network.to_string(),
        )?));

        let orchestrator = Self {
            store,
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
        let pending_withdrawals = (chain_state.withdrawal_counter
            - chain_state.add_withdrawal_counter
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
                    CityProcessWithdrawalRequest::new(i + chain_state.withdrawal_counter),
                )),
            )
        }));

        let mut store = KVQReDBStore::new(wxn.open_table(KV)?);

        for (id, message) in messages {
            match message {
                CityRequest::CityTokenTransferRequest((rpc_node_id, req)) => {
                    self.process_l2_transfer_request(
                        &mut store,
                        &chain_state,
                        rpc_node_id,
                        id,
                        &req,
                    )
                    .await?;
                }
                CityRequest::CityClaimDepositRequest((rpc_node_id, req)) => {
                    self.process_claim_deposit_request(
                        &mut store,
                        &chain_state,
                        rpc_node_id,
                        id,
                        &req,
                    )
                    .await?;
                }
                CityRequest::CityAddWithdrawalRequest((rpc_node_id, req)) => {
                    self.process_add_withdrawal_request(
                        &mut store,
                        &chain_state,
                        rpc_node_id,
                        id,
                        &req,
                    )
                    .await?;
                }
                CityRequest::CityRegisterUserRequest((rpc_node_id, req)) => {
                    self.process_register_user_request(
                        &mut store,
                        &chain_state,
                        rpc_node_id,
                        id,
                        &req,
                    )
                    .await?;
                }
                CityRequest::CityAddDepositRequest((rpc_node_id, req)) => {
                    self.process_add_deposit_request(
                        &mut store,
                        &chain_state,
                        rpc_node_id,
                        id,
                        &req,
                    )
                    .await?;
                }
                CityRequest::CityProcessWithdrawalRequest((rpc_node_id, req)) => {
                    self.process_complete_l1_withdrawal_request(
                        &mut store,
                        &chain_state,
                        rpc_node_id,
                        id,
                        &req,
                    )
                    .await?;
                }
            }
        }

        let new_block_state = self.store.get_block_state().await?;

        L2BlockStateModel::set_block_state(
            &mut store,
            CityL2BlockState {
                checkpoint_id: chain_state.last_orchestrator_block_id,
                next_add_withdrawal_id: new_block_state.add_withdrawal_counter,
                next_process_withdrawal_id: new_block_state.withdrawal_counter,
                next_deposit_id: new_block_state.deposit_counter,
                total_deposits_claimed_epoch: new_block_state.claim_l1_deposit_counter,
                next_user_id: new_block_state.user_counter,
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

    pub async fn process_add_deposit_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityAddDepositRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRAddL1DepositCircuitInput<F>>> {
        let (deposit_id, _) = self.store.incr_block_state_counter(DEPOSIT_COUNTER).await?;
        let (task_index, _) = self.store.incr_block_state_counter(TASK_COUNTER).await?;

        let deposit_tree_delta_merkle_proof = CityStore::<S>::add_deposit_from_request(
            store,
            chain_state.last_orchestrator_block_id,
            deposit_id,
            req,
        )?;

        let witness = CRAddL1DepositCircuitInput {
            deposit_tree_delta_merkle_proof,
            allowed_circuit_hashes_root: self
                .toolbox
                .get_fingerprint_config()
                .op_add_l1_deposit
                .allowed_circuit_hashes_root,
        };

        let job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            chain_state.last_orchestrator_block_id,
            ProvingJobCircuitType::AddL1Deposit.to_circuit_group_id(),
            rpc_node_id,
            task_index as u32,
            ProvingJobCircuitType::AddL1Deposit,
            ProvingJobDataType::InputWitness,
            0,
        );

        self.store
            .set_bytes_by_id(job_id, &witness.to_bytes()?)
            .await?;

        if let Some(message_id) = message_id {
            self.dispatcher
                .delete_message::<Q_TX>(chain_state.last_orchestrator_block_id, message_id)
                .await?;
        }
        self.dispatcher
            .dispatch::<Q_JOB>(job_id.topic as u64, job_id)
            .await?;

        Ok(CircuitInputWithJobId::new(witness, job_id))
    }

    pub async fn process_add_withdrawal_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityAddWithdrawalRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRAddL1WithdrawalCircuitInput<F>>> {
        let (task_index, _) = self.store.incr_block_state_counter(TASK_COUNTER).await?;
        let user_tree_delta_merkle_proof = CityStore::<S>::decrement_user_balance(
            store,
            chain_state.last_orchestrator_block_id,
            req.user_id,
            req.value,
            None,
        )?;
        let withdrawal_tree_delta_merkle_proof =
            CityStore::<S>::add_withdrawal_to_tree_from_request(
                store,
                chain_state.last_orchestrator_block_id,
                req,
            )?;

        let witness = CRAddL1WithdrawalCircuitInput {
            allowed_circuit_hashes_root: self
                .toolbox
                .get_fingerprint_config()
                .op_add_l1_withdrawal
                .allowed_circuit_hashes_root,
            user_tree_delta_merkle_proof,
            withdrawal_tree_delta_merkle_proof,
            signature_proof_id: req.signature_proof_id,
        };

        let job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            chain_state.last_orchestrator_block_id,
            ProvingJobCircuitType::AddL1Withdrawal.to_circuit_group_id(),
            rpc_node_id,
            task_index as u32,
            ProvingJobCircuitType::AddL1Withdrawal,
            ProvingJobDataType::InputWitness,
            0,
        );

        self.store
            .set_bytes_by_id(job_id, &witness.to_bytes()?)
            .await?;

        if let Some(message_id) = message_id {
            self.dispatcher
                .delete_message::<Q_TX>(chain_state.last_orchestrator_block_id, message_id)
                .await?;
        }
        self.dispatcher
            .dispatch::<Q_JOB>(job_id.topic as u64, job_id)
            .await?;

        Ok(CircuitInputWithJobId::new(witness, job_id))
    }
    pub async fn process_claim_deposit_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityClaimDepositRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRClaimL1DepositCircuitInput<F>>> {
        let (task_index, _) = self.store.incr_block_state_counter(TASK_COUNTER).await?;
        let deposit_tree_delta_merkle_proof = CityStore::<S>::mark_deposit_as_claimed(
            store,
            chain_state.last_orchestrator_block_id,
            req.deposit_id,
        )?;
        let user_tree_delta_merkle_proof = CityStore::<S>::increment_user_balance(
            store,
            chain_state.last_orchestrator_block_id,
            req.user_id,
            req.value,
            None,
        )?;
        let deposit = BTCRollupIntrospectionResultDeposit::from_byte_representation(
            &req.public_key.0,
            req.txid,
            req.value,
        );

        let witness = CRClaimL1DepositCircuitInput {
            deposit_tree_delta_merkle_proof,
            allowed_circuit_hashes_root: self
                .toolbox
                .get_fingerprint_config()
                .op_claim_l1_deposit
                .allowed_circuit_hashes_root,
            deposit,
            user_tree_delta_merkle_proof,
            signature_proof_id: req.signature_proof_id,
        };

        let job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            chain_state.last_orchestrator_block_id,
            ProvingJobCircuitType::ClaimL1Deposit.to_circuit_group_id(),
            rpc_node_id,
            task_index as u32,
            ProvingJobCircuitType::ClaimL1Deposit,
            ProvingJobDataType::InputWitness,
            0,
        );

        self.store
            .set_bytes_by_id(job_id, &witness.to_bytes()?)
            .await?;

        if let Some(message_id) = message_id {
            self.dispatcher
                .delete_message::<Q_TX>(chain_state.last_orchestrator_block_id, message_id)
                .await?;
        }
        self.dispatcher
            .dispatch::<Q_JOB>(job_id.topic as u64, job_id)
            .await?;

        Ok(CircuitInputWithJobId::new(witness, job_id))
    }

    pub async fn process_l2_transfer_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityTokenTransferRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRL2TransferCircuitInput<F>>> {
        let (task_index, _) = self.store.incr_block_state_counter(TASK_COUNTER).await?;
        let sender_user_tree_delta_merkle_proof = CityStore::<S>::decrement_user_balance(
            store,
            chain_state.last_orchestrator_block_id,
            req.user_id,
            req.value,
            None,
        )?;

        let receiver_user_tree_delta_merkle_proof = CityStore::<S>::increment_user_balance(
            store,
            chain_state.last_orchestrator_block_id,
            req.to,
            req.value,
            None,
        )?;

        let witness = CRL2TransferCircuitInput {
            sender_user_tree_delta_merkle_proof,
            receiver_user_tree_delta_merkle_proof,
            allowed_circuit_hashes_root: self
                .toolbox
                .get_fingerprint_config()
                .op_l2_transfer
                .allowed_circuit_hashes_root,
            signature_proof_id: req.signature_proof_id,
        };

        let job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            chain_state.last_orchestrator_block_id,
            ProvingJobCircuitType::TransferTokensL2.to_circuit_group_id(),
            rpc_node_id,
            task_index as u32,
            ProvingJobCircuitType::TransferTokensL2,
            ProvingJobDataType::InputWitness,
            0,
        );

        self.store
            .set_bytes_by_id(job_id, &witness.to_bytes()?)
            .await?;

        if let Some(message_id) = message_id {
            self.dispatcher
                .delete_message::<Q_TX>(chain_state.last_orchestrator_block_id, message_id)
                .await?;
        }
        self.dispatcher
            .dispatch::<Q_JOB>(job_id.topic as u64, job_id)
            .await?;

        Ok(CircuitInputWithJobId::new(witness, job_id))
    }

    pub async fn process_complete_l1_withdrawal_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityProcessWithdrawalRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRProcessL1WithdrawalCircuitInput<F>>> {
        let (task_index, _) = self.store.incr_block_state_counter(TASK_COUNTER).await?;
        let withdrawal_tree_delta_merkle_proof = CityStore::<S>::mark_withdrawal_as_completed(
            store,
            chain_state.last_orchestrator_block_id,
            req.withdrawal_id,
        )?;
        let witness = CRProcessL1WithdrawalCircuitInput {
            withdrawal_tree_delta_merkle_proof,
            allowed_circuit_hashes_root: self
                .toolbox
                .get_fingerprint_config()
                .op_process_l1_withdrawal
                .allowed_circuit_hashes_root,
        };

        let job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            chain_state.last_orchestrator_block_id,
            ProvingJobCircuitType::ProcessL1Withdrawal.to_circuit_group_id(),
            rpc_node_id,
            task_index as u32,
            ProvingJobCircuitType::ProcessL1Withdrawal,
            ProvingJobDataType::InputWitness,
            0,
        );

        self.store
            .set_bytes_by_id(job_id, &witness.to_bytes()?)
            .await?;

        if let Some(message_id) = message_id {
            self.dispatcher
                .delete_message::<Q_TX>(chain_state.last_orchestrator_block_id, message_id)
                .await?;
        }
        self.dispatcher
            .dispatch::<Q_JOB>(job_id.topic as u64, job_id)
            .await?;

        Ok(CircuitInputWithJobId::new(witness, job_id))
    }

    pub async fn process_register_user_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityRegisterUserRequest<F>,
    ) -> anyhow::Result<CircuitInputWithJobId<CRUserRegistrationCircuitInput<F>>> {
        let (task_index, _) = self.store.incr_block_state_counter(TASK_COUNTER).await?;

        let user_tree_delta_merkle_proof = CityStore::<S>::register_user(
            store,
            chain_state.last_orchestrator_block_id,
            req.user_id,
            req.public_key,
        )?;
        let witness = CRUserRegistrationCircuitInput {
            user_tree_delta_merkle_proof,
            allowed_circuit_hashes_root: self
                .toolbox
                .get_fingerprint_config()
                .op_register_user
                .allowed_circuit_hashes_root,
        };

        let job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            chain_state.last_orchestrator_block_id,
            ProvingJobCircuitType::RegisterUser.to_circuit_group_id(),
            rpc_node_id,
            task_index as u32,
            ProvingJobCircuitType::RegisterUser,
            ProvingJobDataType::InputWitness,
            0,
        );

        self.store
            .set_bytes_by_id(job_id, &witness.to_bytes()?)
            .await?;

        if let Some(message_id) = message_id {
            self.dispatcher
                .delete_message::<Q_TX>(chain_state.last_orchestrator_block_id, message_id)
                .await?;
        }
        self.dispatcher
            .dispatch::<Q_JOB>(job_id.topic as u64, job_id)
            .await?;

        Ok(CircuitInputWithJobId::new(witness, job_id))
    }
}
