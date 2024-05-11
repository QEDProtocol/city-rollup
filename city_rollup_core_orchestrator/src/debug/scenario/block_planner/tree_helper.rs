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
use serde::de::DeserializeOwned;
use serde::Serialize;

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
