use std::fmt::Debug;

use city_crypto::hash::merkle::treeprover::generate_tree_inputs_with_position;
use city_crypto::hash::merkle::treeprover::AggStateTrackableInput;
use city_crypto::hash::merkle::treeprover::AggStateTrackableWithEventsInput;
use city_crypto::hash::merkle::treeprover::AggStateTransition;
use city_crypto::hash::merkle::treeprover::AggStateTransitionWithEvents;
use city_crypto::hash::merkle::treeprover::DummyAggStateTransition;
use city_crypto::hash::merkle::treeprover::DummyAggStateTransitionWithEvents;
use city_crypto::hash::merkle::treeprover::TPLeafAggregator;
use city_crypto::hash::merkle::treeprover::WithDummyStateTransition;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::job_witnesses::op::CircuitInputWithDependencies;
use city_rollup_common::qworker::job_witnesses::op::CircuitInputWithJobId;
use city_rollup_common::qworker::proof_store::QProofStore;
use city_store::config::F;
use plonky2::hash::hash_types::RichField;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct CityRootStateTransitions<F: RichField> {
    pub start_deposit_tree_root: QHashOut<F>,
    pub start_withdrawal_tree_root: QHashOut<F>,
    pub register_users: AggStateTransition<F>,
    pub claim_deposits: AggStateTransition<F>,
    pub token_transfers: AggStateTransition<F>,
    pub add_withdrawals: AggStateTransition<F>,
    pub process_withdrawals: AggStateTransitionWithEvents<F>,
    pub add_deposits: AggStateTransitionWithEvents<F>,
}

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

pub fn plan_tree_prover_from_leaves<
    PS: QProofStore,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableInput<F>,
    IO: Debug
        + Clone
        + Serialize
        + DeserializeOwned
        + PartialEq
        + WithDummyStateTransition<F>
        + AggStateTrackableInput<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    proof_store: &mut PS,
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
    allowed_circuit_hashes_root: QHashOut<F>,
) -> anyhow::Result<(Vec<Vec<QProvingJobDataID>>, AggStateTransition<F>)> {
    if leaves.len() == 0 {
        //let dummy = IO::get_dummy_value(dummy_state_root);
        let dummy = DummyAggStateTransition {
            state_transition_hash: dummy_state_root,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root,
        };
        proof_store.set_bytes_by_id(dummy_id, &bincode::serialize(&dummy)?)?;
        let dummy = IO::get_dummy_value(dummy_state_root);

        return Ok((vec![vec![dummy_id]], dummy.get_state_transition()));
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);
    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    let total_levels = levels.len();
    let mut last_node_state = AggStateTransition::default();

    for (level, level_nodes) in levels.into_iter().enumerate() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        let total_nodes = level_nodes.len();

        for (index, node) in level_nodes.into_iter().enumerate() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize]
                [node.tree_position.left_job.index as usize]
                .get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize]
                [node.tree_position.right_job.index as usize]
                .get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            if (level + 1) == total_levels && (index + 1) == total_nodes {
                last_node_state = node.input.get_state_transition();
            }
            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok((job_ids, last_node_state))
}

pub fn plan_tree_prover_from_leaves_with_events<
    PS: QProofStore,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableWithEventsInput<F>,
    IO: Debug
        + Clone
        + Serialize
        + DeserializeOwned
        + PartialEq
        + WithDummyStateTransition<F>
        + AggStateTrackableWithEventsInput<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    proof_store: &mut PS,
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
    allowed_circuit_hashes_root: QHashOut<F>,
) -> anyhow::Result<(Vec<Vec<QProvingJobDataID>>, AggStateTransitionWithEvents<F>)> {
    if leaves.len() == 0 {
        let dummy = DummyAggStateTransitionWithEvents {
            state_transition_hash: dummy_state_root,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root,
            event_transition_hash: QHashOut::ZERO,
        };
        proof_store.set_bytes_by_id(dummy_id, &bincode::serialize(&dummy)?)?;
        let dummy = IO::get_dummy_value(dummy_state_root);

        return Ok((
            vec![vec![dummy_id]],
            dummy.get_state_transition_with_events(),
        ));
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);
    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    let total_levels = levels.len();
    let mut last_node_state = AggStateTransitionWithEvents::default();
    for (level, level_nodes) in levels.into_iter().enumerate() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        let last_index = level_nodes.len();
        for (index, node) in level_nodes.into_iter().enumerate() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize]
                [node.tree_position.left_job.index as usize]
                .get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize]
                [node.tree_position.right_job.index as usize]
                .get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            if (level + 1) == total_levels && (index + 1) == last_index {
                last_node_state = node.input.get_state_transition_with_events();
            }
            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok((job_ids, last_node_state))
}

