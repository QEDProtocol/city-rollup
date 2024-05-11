use city_crypto::hash::merkle::treeprover::AggStateTransitionInput;
use city_crypto::hash::merkle::treeprover::AggStateTransitionWithEventsInput;
use city_crypto::hash::merkle::treeprover::AggWTLeafAggregator;
use city_crypto::hash::merkle::treeprover::AggWTTELeafAggregator;
use city_crypto::hash::qhashout::QHashOut;
use city_redis_store::ChainState;
use city_redis_store::ADD_DEPOSIT_COUNTER;
use city_redis_store::TASK_COUNTER;
use city_rollup_common::api::data::block::requested_actions::CityAddDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityAddWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityClaimDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityProcessWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityRegisterUserRequest;
use city_rollup_common::api::data::block::requested_actions::CityRequest;
use city_rollup_common::api::data::block::requested_actions::CityTokenTransferRequest;
use city_rollup_common::introspection::rollup::introspection_result::BTCRollupIntrospectionResultDeposit;
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
use city_rollup_common::qworker::redis_proof_store::SyncRedisProofStore;
use city_rollup_worker_dispatch::implementations::redis::Q_JOB;
use city_rollup_worker_dispatch::implementations::redis::Q_TX;
use city_rollup_worker_dispatch::traits::proving_dispatcher::ProvingDispatcher;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use city_store::config::F;
use city_store::store::city::base::CityStore;
use kvq::traits::KVQBinaryStore;
use kvq::traits::KVQSerializable;
use kvq_store_redb::KVQReDBStore;
use redb::Table;

use crate::orchestrator::CityScenarioInputWithJobIds;
use crate::orchestrator::Orchestrator;
use crate::tree_helper::plan_tree_prover_from_leaves;
use crate::tree_helper::CityOpJobIds;

impl Orchestrator {
    pub async fn process_add_deposit_request<S: KVQBinaryStore>(
        &mut self,
        store: &mut S,
        chain_state: &ChainState,
        rpc_node_id: u32,
        message_id: Option<String>,
        req: &CityAddDepositRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRAddL1DepositCircuitInput<F>>> {
        let (deposit_id, _) = self
            .store
            .incr_block_state_counter(ADD_DEPOSIT_COUNTER)
            .await?;
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

    pub async fn process_txs<'db, 'txn>(
        &mut self,
        messages: Vec<(Option<String>, CityRequest<F>)>,
        store: &mut KVQReDBStore<Table<'db, 'txn, &'static [u8], &'static [u8]>>,
        chain_state: ChainState,
    ) -> anyhow::Result<CityScenarioInputWithJobIds<F>> {
        let mut job_ids = CityScenarioInputWithJobIds::default();
        for (id, message) in messages {
            match message {
                CityRequest::CityTokenTransferRequest((rpc_node_id, req)) => {
                    job_ids.token_transfers.push(
                        self.process_l2_transfer_request(
                            store,
                            &chain_state,
                            rpc_node_id,
                            id,
                            &req,
                        )
                        .await?,
                    )
                }
                CityRequest::CityClaimDepositRequest((rpc_node_id, req)) => {
                    job_ids.claim_l1_deposits.push(
                        self.process_claim_deposit_request(
                            store,
                            &chain_state,
                            rpc_node_id,
                            id,
                            &req,
                        )
                        .await?,
                    )
                }
                CityRequest::CityAddWithdrawalRequest((rpc_node_id, req)) => {
                    job_ids.add_withdrawals.push(
                        self.process_add_withdrawal_request(
                            store,
                            &chain_state,
                            rpc_node_id,
                            id,
                            &req,
                        )
                        .await?,
                    )
                }
                CityRequest::CityRegisterUserRequest((rpc_node_id, req)) => {
                    job_ids.register_users.push(
                        self.process_register_user_request(
                            store,
                            &chain_state,
                            rpc_node_id,
                            id,
                            &req,
                        )
                        .await?,
                    )
                }
                CityRequest::CityAddDepositRequest((rpc_node_id, req)) => {
                    job_ids.add_deposits.push(
                        self.process_add_deposit_request(
                            store,
                            &chain_state,
                            rpc_node_id,
                            id,
                            &req,
                        )
                        .await?,
                    )
                }
                CityRequest::CityProcessWithdrawalRequest((rpc_node_id, req)) => {
                    job_ids.process_withdrawals.push(
                        self.process_complete_l1_withdrawal_request(
                            store,
                            &chain_state,
                            rpc_node_id,
                            id,
                            &req,
                        )
                        .await?,
                    )
                }
            }
        }
        Ok(job_ids)
    }

    pub fn generate_agg_jobs(
        &mut self,
        job_ids: CityScenarioInputWithJobIds<F>,
        chain_state: ChainState,
        dummy_state_root: QHashOut<F>,
    ) -> anyhow::Result<CityOpJobIds> {
        let register_user_job_ids = plan_tree_prover_from_leaves::<
            SyncRedisProofStore,
            AggWTLeafAggregator,
            _,
            AggStateTransitionInput<F>,
        >(
            &job_ids.register_users,
            &mut self.proof_store,
            QProvingJobDataID::new_proof_job_id(
                chain_state.last_orchestrator_block_id,
                ProvingJobCircuitType::DummyRegisterUserAggregate,
                0xDD,
                0,
                0,
            ),
            dummy_state_root,
        )?;
        let claim_deposit_job_ids = plan_tree_prover_from_leaves::<
            SyncRedisProofStore,
            AggWTLeafAggregator,
            _,
            AggStateTransitionInput<F>,
        >(
            &job_ids.claim_l1_deposits,
            &mut self.proof_store,
            QProvingJobDataID::new_proof_job_id(
                chain_state.last_orchestrator_block_id,
                ProvingJobCircuitType::DummyClaimL1DepositAggregate,
                0xDD,
                0,
                0,
            ),
            dummy_state_root,
        )?;
        let token_transfer_job_ids = plan_tree_prover_from_leaves::<
            SyncRedisProofStore,
            AggWTLeafAggregator,
            _,
            AggStateTransitionInput<F>,
        >(
            &job_ids.token_transfers,
            &mut self.proof_store,
            QProvingJobDataID::new_proof_job_id(
                chain_state.last_orchestrator_block_id,
                ProvingJobCircuitType::DummyTransferTokensL2Aggregate,
                0xDD,
                0,
                0,
            ),
            dummy_state_root,
        )?;
        let add_withdrawal_job_ids = plan_tree_prover_from_leaves::<
            SyncRedisProofStore,
            AggWTLeafAggregator,
            _,
            AggStateTransitionInput<F>,
        >(
            &job_ids.add_withdrawals,
            &mut self.proof_store,
            QProvingJobDataID::new_proof_job_id(
                chain_state.last_orchestrator_block_id,
                ProvingJobCircuitType::DummyAddL1WithdrawalAggregate,
                0xDD,
                0,
                0,
            ),
            dummy_state_root,
        )?;
        let add_deposit_job_ids = plan_tree_prover_from_leaves::<
            SyncRedisProofStore,
            AggWTTELeafAggregator,
            _,
            AggStateTransitionWithEventsInput<F>,
        >(
            &job_ids.add_deposits,
            &mut self.proof_store,
            QProvingJobDataID::new_proof_job_id(
                chain_state.last_orchestrator_block_id,
                ProvingJobCircuitType::DummyAddL1DepositAggregate,
                0xDD,
                0,
                0,
            ),
            dummy_state_root,
        )?;
        let process_withdrawal_job_ids = plan_tree_prover_from_leaves::<
            SyncRedisProofStore,
            AggWTTELeafAggregator,
            _,
            AggStateTransitionWithEventsInput<F>,
        >(
            &job_ids.process_withdrawals,
            &mut self.proof_store,
            QProvingJobDataID::new_proof_job_id(
                chain_state.last_orchestrator_block_id,
                ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate,
                0xDD,
                0,
                0,
            ),
            dummy_state_root,
        )?;
        Ok(CityOpJobIds {
            register_user_job_ids,
            claim_deposit_job_ids,
            token_transfer_job_ids,
            add_withdrawal_job_ids,
            add_deposit_job_ids,
            process_withdrawal_job_ids,
        })
    }
}
