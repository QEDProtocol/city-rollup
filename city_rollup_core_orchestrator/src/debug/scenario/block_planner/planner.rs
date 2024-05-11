use city_crypto::hash::{
    merkle::treeprover::{
        AggStateTransitionInput, AggStateTransitionWithEventsInput, AggWTLeafAggregator,
        AggWTTELeafAggregator,
    },
    qhashout::QHashOut,
    traits::hasher::MerkleHasher,
};
use city_rollup_common::{
    api::data::store::CityL2BlockState,
    qworker::{
        fingerprints::CRWorkerToolboxCoreCircuitFingerprints,
        job_id::{ProvingJobCircuitType, QProvingJobDataID},
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
    ) -> anyhow::Result<(CityOpJobIds, CityRootStateTransitions<F>)> {
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
                    ProvingJobCircuitType::DummyRegisterUserAggregate,
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
                    ProvingJobCircuitType::DummyRegisterUserAggregate,
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
                    ProvingJobCircuitType::DummyRegisterUserAggregate,
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
                    ProvingJobCircuitType::DummyRegisterUserAggregate,
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
                    ProvingJobCircuitType::DummyRegisterUserAggregate,
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
        let transition = CityRootStateTransitions {
            start_deposit_tree_root,
            start_withdrawal_tree_root,
            register_users: root_transition_register_users,
            claim_deposits: root_transition_claim_deposits,
            token_transfers: root_transition_transfer_tokens,
            add_withdrawals: root_transition_add_withdrawals,
            process_withdrawals: root_transition_process_withdrawals,
            add_deposits: root_transition_add_deposits,
        };
        Ok((job_ids, transition))
    }
}