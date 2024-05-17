use city_crypto::hash::{
    merkle::treeprover::{
        AggStateTransitionInput, AggStateTransitionWithEventsInput, AggWTLeafAggregator,
        AggWTTELeafAggregator,
    },
    qhashout::QHashOut,
    traits::hasher::MerkleHasher,
};
use city_rollup_common::{
    api::data::store::{CityL1Withdrawal, CityL2BlockState},
    qworker::{
        fingerprints::CRWorkerToolboxCoreCircuitFingerprints,
        job_id::{ProvingJobCircuitType, QProvingJobDataID},
        job_witnesses::agg::CRBlockStateTransitionCircuitInput,
        proof_store::QProofStore,
    },
};
use city_store::{config::F, store::city::base::CityStore};
use kvq::traits::KVQBinaryStore;
use plonky2::hash::poseidon::PoseidonHash;

use crate::debug::scenario::{
    process_requests::block_processor::CityOrchestratorBlockProcessor,
    requested_actions::CityScenarioRequestedActions,
};

use super::{
    transition::{CityOpJobIds, CityRootStateTransitions},
    tree_helper::{plan_tree_prover_from_leaves, plan_tree_prover_from_leaves_with_events},
};
pub struct CityOrchestratorBlockPlanner<S: KVQBinaryStore, PS: QProofStore> {
    pub processor: CityOrchestratorBlockProcessor<S, PS>,
}

impl<S: KVQBinaryStore, PS: QProofStore> CityOrchestratorBlockPlanner<S, PS> {
    pub fn new(
        fingerprints: CRWorkerToolboxCoreCircuitFingerprints<F>,
        last_block_state: CityL2BlockState,
    ) -> Self {
        let processor = CityOrchestratorBlockProcessor::new(last_block_state, fingerprints);

        Self { processor }
    }

    pub fn process_requests(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        requested_actions: &CityScenarioRequestedActions<F>,
    ) -> anyhow::Result<(
        CityL2BlockState,
        CityOpJobIds,
        CityRootStateTransitions<F>,
        Vec<QProvingJobDataID>,
        Vec<CityL1Withdrawal>,
    )> {
        let start_deposit_tree_root =
            CityStore::get_deposit_tree_root(store, self.processor.checkpoint_id)?;

        let start_withdrawal_tree_root =
            CityStore::get_withdrawal_tree_root(store, self.processor.checkpoint_id)?;

        let dummy_state_root = QHashOut::ZERO;

        let register_user_dummy_state_root = if requested_actions.register_users.len() == 0 {
            CityStore::<S>::get_user_tree_root(store, self.processor.checkpoint_id)?
        } else {
            dummy_state_root
        };
        let (register_user_job_ids, root_transition_register_users) =
            plan_tree_prover_from_leaves::<PS, AggWTLeafAggregator, _, AggStateTransitionInput<F>>(
                &requested_actions
                    .register_users
                    .iter()
                    .map(|req| {
                        self.processor
                            .process_register_user(store, proof_store, req)
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                proof_store,
                QProvingJobDataID::new_proof_job_id(
                    self.processor.checkpoint_id,
                    ProvingJobCircuitType::DummyRegisterUserAggregate,
                    0xDD,
                    0,
                    0,
                ),
                register_user_dummy_state_root,
                self.processor
                    .op_processor
                    .fingerprints
                    .op_register_user
                    .allowed_circuit_hashes_root,
            )?;
        let claim_deposit_dummy_state_root = if requested_actions.claim_l1_deposits.len() == 0 {
            PoseidonHash::two_to_one(
                &root_transition_register_users.state_transition_end,
                &start_deposit_tree_root,
            )
        } else {
            dummy_state_root
        };

        let (claim_deposit_job_ids, root_transition_claim_deposits) =
            plan_tree_prover_from_leaves::<PS, AggWTLeafAggregator, _, AggStateTransitionInput<F>>(
                &requested_actions
                    .claim_l1_deposits
                    .iter()
                    .map(|req| {
                        self.processor
                            .process_claim_deposit(store, proof_store, req)
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                proof_store,
                QProvingJobDataID::new_proof_job_id(
                    self.processor.checkpoint_id,
                    ProvingJobCircuitType::DummyClaimL1DepositAggregate,
                    0xDD,
                    0,
                    0,
                ),
                claim_deposit_dummy_state_root,
                self.processor
                    .op_processor
                    .fingerprints
                    .op_claim_l1_deposit
                    .allowed_circuit_hashes_root,
            )?;

        let token_transfer_dummy_state_root = if requested_actions.token_transfers.len() == 0 {
            CityStore::get_user_tree_root(store, self.processor.checkpoint_id)?
        } else {
            dummy_state_root
        };
        let (token_transfer_job_ids, root_transition_transfer_tokens) =
            plan_tree_prover_from_leaves::<PS, AggWTLeafAggregator, _, AggStateTransitionInput<F>>(
                &requested_actions
                    .token_transfers
                    .iter()
                    .map(|req| self.processor.process_l2_transfer(store, proof_store, req))
                    .collect::<anyhow::Result<Vec<_>>>()?,
                proof_store,
                QProvingJobDataID::new_proof_job_id(
                    self.processor.checkpoint_id,
                    ProvingJobCircuitType::DummyTransferTokensL2Aggregate,
                    0xDD,
                    0,
                    0,
                ),
                token_transfer_dummy_state_root,
                self.processor
                    .op_processor
                    .fingerprints
                    .op_l2_transfer
                    .allowed_circuit_hashes_root,
            )?;

        let add_withdrawal_dummy_state_root = if requested_actions.add_withdrawals.len() == 0 {
            PoseidonHash::two_to_one(
                &CityStore::get_user_tree_root(store, self.processor.checkpoint_id)?,
                &CityStore::get_withdrawal_tree_root(store, self.processor.checkpoint_id)?,
            )
        } else {
            dummy_state_root
        };
        let (add_withdrawal_job_ids, root_transition_add_withdrawals) =
            plan_tree_prover_from_leaves::<PS, AggWTLeafAggregator, _, AggStateTransitionInput<F>>(
                &requested_actions
                    .add_withdrawals
                    .iter()
                    .map(|req| {
                        self.processor
                            .process_add_withdrawal(store, proof_store, req)
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                proof_store,
                QProvingJobDataID::new_proof_job_id(
                    self.processor.checkpoint_id,
                    ProvingJobCircuitType::DummyAddL1WithdrawalAggregate,
                    0xDD,
                    0,
                    0,
                ),
                add_withdrawal_dummy_state_root,
                self.processor
                    .op_processor
                    .fingerprints
                    .op_add_l1_withdrawal
                    .allowed_circuit_hashes_root,
            )?;

        let process_withdrawals_dummy_state_root =
            if requested_actions.process_withdrawals.len() == 0 {
                CityStore::get_withdrawal_tree_root(store, self.processor.checkpoint_id)?
            } else {
                dummy_state_root
            };
        let processed_withdrawals = CityStore::get_withdrawals_by_id(
            store,
            self.processor.checkpoint_id,
            &requested_actions
                .process_withdrawals
                .iter()
                .map(|x| x.withdrawal_id)
                .collect::<Vec<_>>(),
        )?;

        let (process_withdrawal_job_ids, root_transition_process_withdrawals) =
            plan_tree_prover_from_leaves_with_events::<
                PS,
                AggWTTELeafAggregator,
                _,
                AggStateTransitionWithEventsInput<F>,
            >(
                &requested_actions
                    .process_withdrawals
                    .iter()
                    .map(|req| {
                        self.processor
                            .process_complete_l1_withdrawal(store, proof_store, req)
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                proof_store,
                QProvingJobDataID::new_proof_job_id(
                    self.processor.checkpoint_id,
                    ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate,
                    0xDD,
                    0,
                    0,
                ),
                process_withdrawals_dummy_state_root,
                self.processor
                    .op_processor
                    .fingerprints
                    .op_process_l1_withdrawal
                    .allowed_circuit_hashes_root,
            )?;

        let add_deposits_dummy_state_root = if requested_actions.add_deposits.len() == 0 {
            CityStore::get_deposit_tree_root(store, self.processor.checkpoint_id)?
        } else {
            dummy_state_root
        };
        let (add_deposit_job_ids, root_transition_add_deposits) =
            plan_tree_prover_from_leaves_with_events::<
                PS,
                AggWTTELeafAggregator,
                _,
                AggStateTransitionWithEventsInput<F>,
            >(
                &requested_actions
                    .add_deposits
                    .iter()
                    .map(|req| self.processor.process_add_deposit(store, proof_store, req))
                    .collect::<anyhow::Result<Vec<_>>>()?,
                proof_store,
                QProvingJobDataID::new_proof_job_id(
                    self.processor.checkpoint_id,
                    ProvingJobCircuitType::DummyAddL1DepositAggregate,
                    0xDD,
                    0,
                    0,
                ),
                add_deposits_dummy_state_root,
                self.processor
                    .op_processor
                    .fingerprints
                    .op_add_l1_deposit
                    .allowed_circuit_hashes_root,
            )?;
        let job_ids = CityOpJobIds {
            register_user_job_ids,
            claim_deposit_job_ids,
            token_transfer_job_ids,
            add_withdrawal_job_ids,
            process_withdrawal_job_ids,
            add_deposit_job_ids,
        };

        let end_user_state_tree_root =
            CityStore::get_user_tree_root(store, self.processor.checkpoint_id)?;

        let transition = CityRootStateTransitions {
            start_deposit_tree_root,
            start_withdrawal_tree_root,
            end_user_state_tree_root,
            register_users: root_transition_register_users,
            claim_deposits: root_transition_claim_deposits,
            token_transfers: root_transition_transfer_tokens,
            add_withdrawals: root_transition_add_withdrawals,
            process_withdrawals: root_transition_process_withdrawals,
            add_deposits: root_transition_add_deposits,
        };

        let root_ids = job_ids.get_root_proof_outputs();
        let block_state_witness_part_1 = transition.get_block_state_witness_part_1(&root_ids);

        let block_state_part_1_id =
            QProvingJobDataID::block_agg_state_part_1_input_witness(self.processor.checkpoint_id);
        proof_store.set_bytes_by_id(
            block_state_part_1_id,
            &bincode::serialize(&block_state_witness_part_1)?,
        )?;

        let block_state_witness_part_2 = transition.get_block_state_witness_part_2(&root_ids);

        let block_state_part_2_id =
            QProvingJobDataID::block_agg_state_part_2_input_witness(self.processor.checkpoint_id);
        proof_store.set_bytes_by_id(
            block_state_part_2_id,
            &bincode::serialize(&block_state_witness_part_2)?,
        )?;

        let block_state_transition_input = CRBlockStateTransitionCircuitInput::from_steps(
            block_state_part_1_id.get_output_id(),
            &block_state_witness_part_1,
            block_state_part_2_id.get_output_id(),
            &block_state_witness_part_2,
        );
        let block_state_transition_id =
            QProvingJobDataID::block_state_transition_input_witness(self.processor.checkpoint_id);

        proof_store.set_bytes_by_id(
            block_state_transition_id,
            &bincode::serialize(&block_state_transition_input)?,
        )?;

        let new_state = self.processor.op_processor.get_finalized_block_state();
        CityStore::<S>::set_block_state(store, &new_state)?;

        Ok((
            self.processor.op_processor.get_finalized_block_state(),
            job_ids,
            transition,
            vec![
                block_state_part_1_id,
                block_state_part_2_id,
                block_state_transition_id,
            ],
            processed_withdrawals,
        ))
    }
}
