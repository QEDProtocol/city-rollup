use city_crypto::hash::{
    merkle::treeprover::{
        AggAggStateTransitionWithEventsInput, AggStateTrackableInput, AggStateTransitionInput,
        AggWTLeafAggregator, AggWTTELeafAggregator, StateTransitionTrackable,
        StateTransitionTrackableWithEvents,
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

use super::tree_helper::{plan_tree_prover_from_leaves, plan_tree_prover_from_leaves_with_events};

pub struct CityOpRootJobIds {
    pub register_user_job_root_id: QProvingJobDataID,
    pub claim_deposit_job_root_id: QProvingJobDataID,
    pub token_transfer_job_root_id: QProvingJobDataID,
    pub add_withdrawal_job_root_id: QProvingJobDataID,
    pub process_withdrawal_job_root_id: QProvingJobDataID,
    pub add_deposit_job_root_id: QProvingJobDataID,
}
pub struct CityOpJobIds {
    pub register_user_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub claim_deposit_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub token_transfer_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub add_withdrawal_job_ids: Vec<Vec<QProvingJobDataID>>,

    pub process_withdrawal_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub add_deposit_job_ids: Vec<Vec<QProvingJobDataID>>,
}
fn merge_jobs_in<T: Copy + Clone>(base: &mut Vec<Vec<T>>, jobs: &[Vec<T>]) {
    if base.len() < jobs.len() {
        base.resize(jobs.len(), Vec::new());
    }
    for (i, job) in jobs.iter().enumerate() {
        base[i].extend(job);
    }
}
fn vec_2d_size<T>(arr: &[Vec<T>]) -> usize {
    arr.iter().map(|x| x.len()).sum()
}
impl CityOpJobIds {
    pub fn get_total_job_ids(&self) -> usize {
        vec_2d_size(&self.register_user_job_ids)
            + vec_2d_size(&self.claim_deposit_job_ids)
            + vec_2d_size(&self.token_transfer_job_ids)
            + vec_2d_size(&self.add_withdrawal_job_ids)
            + vec_2d_size(&self.process_withdrawal_job_ids)
            + vec_2d_size(&self.add_deposit_job_ids)
    }
    pub fn plan_jobs(&self) -> Vec<QProvingJobDataID> {
        let mut job_ids = Vec::with_capacity(self.get_total_job_ids());
        let max_level = self
            .register_user_job_ids
            .len()
            .max(self.claim_deposit_job_ids.len())
            .max(self.token_transfer_job_ids.len())
            .max(self.add_withdrawal_job_ids.len())
            .max(self.process_withdrawal_job_ids.len())
            .max(self.add_deposit_job_ids.len());

        for i in 0..max_level {
            if i < self.register_user_job_ids.len() {
                job_ids.extend(&self.register_user_job_ids[i]);
            }
            if i < self.claim_deposit_job_ids.len() {
                job_ids.extend(&self.claim_deposit_job_ids[i]);
            }
            if i < self.token_transfer_job_ids.len() {
                job_ids.extend(&self.token_transfer_job_ids[i]);
            }
            if i < self.add_withdrawal_job_ids.len() {
                job_ids.extend(&self.add_withdrawal_job_ids[i]);
            }
            if i < self.process_withdrawal_job_ids.len() {
                job_ids.extend(&self.process_withdrawal_job_ids[i]);
            }
            if i < self.add_deposit_job_ids.len() {
                job_ids.extend(&self.add_deposit_job_ids[i]);
            }
        }

        job_ids
    }
}
impl CityOpJobIds {
    pub fn new() -> Self {
        Self {
            register_user_job_ids: Vec::new(),
            claim_deposit_job_ids: Vec::new(),
            token_transfer_job_ids: Vec::new(),
            add_withdrawal_job_ids: Vec::new(),

            process_withdrawal_job_ids: Vec::new(),
            add_deposit_job_ids: Vec::new(),
        }
    }
}
pub struct CityOrchestratorBlockPlanner<S: KVQBinaryStore, PS: QProofStore> {
    pub processor: CityOrchestratorBlockProcessor<S, PS>,
    pub op_job_ids_by_level: CityOpJobIds,
}

impl<S: KVQBinaryStore, PS: QProofStore> CityOrchestratorBlockPlanner<S, PS> {
    pub fn new(
        fingerprints: CRWorkerToolboxCoreCircuitFingerprints<F>,
        last_block_state: CityL2BlockState,
    ) -> Self {
        let processor = CityOrchestratorBlockProcessor::new(last_block_state, fingerprints);

        Self {
            processor,
            op_job_ids_by_level: CityOpJobIds::new(),
        }
    }

    pub fn process_requests(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        requested_actions: &CityScenarioRequestedActions<F>,
    ) -> anyhow::Result<()> {
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
            )?;
        let claim_deposit_dummy_state_root = if requested_actions.claim_l1_deposits.len() == 0 {
            PoseidonHash::two_to_one(
                &root_transition_register_users.state_transition_end,
                &CityStore::get_deposit_tree_root(store, self.processor.checkpoint_id)?,
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
            )?;

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
                dummy_state_root,
            )?;

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
                dummy_state_root,
            )?;

        let (process_withdrawal_job_ids, root_transition_process_withdrawals) =
            plan_tree_prover_from_leaves_with_events::<
                PS,
                AggWTTELeafAggregator,
                _,
                AggAggStateTransitionWithEventsInput<F>,
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
                dummy_state_root,
            )?;

        let (add_deposit_job_ids, root_transition_add_deposits) =
            plan_tree_prover_from_leaves_with_events::<
                PS,
                AggWTTELeafAggregator,
                _,
                AggAggStateTransitionWithEventsInput<F>,
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
                dummy_state_root,
            )?;
        self.op_job_ids_by_level = CityOpJobIds {
            register_user_job_ids,
            claim_deposit_job_ids,
            token_transfer_job_ids,
            add_withdrawal_job_ids,
            process_withdrawal_job_ids,
            add_deposit_job_ids,
        };
        Ok(())
    }
}
