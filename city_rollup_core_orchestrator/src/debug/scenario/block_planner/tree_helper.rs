use std::fmt::Debug;

use city_crypto::hash::{
    merkle::treeprover::{
        generate_tree_inputs_with_position, TPLeafAggregator, WithDummyStateTransition,
    },
    qhashout::QHashOut,
};
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID,
    job_witnesses::op::{CircuitInputWithDependencies, CircuitInputWithJobId},
    proof_store::QProofStore,
};
use city_store::config::F;
use serde::{de::DeserializeOwned, Serialize};

pub fn plan_tree_prover_from_leaves<
    PS: QProofStore,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq,
    IO: Debug + Clone + Serialize + DeserializeOwned + PartialEq + WithDummyStateTransition<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    proof_store: &mut PS,
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
) -> anyhow::Result<Vec<Vec<QProvingJobDataID>>> {
    if leaves.len() == 0 {
        proof_store.set_bytes_by_id(
            dummy_id,
            &bincode::serialize(&IO::get_dummy_value(dummy_state_root))?,
        )?;

        return Ok(vec![vec![dummy_id]]);
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);
    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    for level_nodes in levels.into_iter() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        for node in level_nodes.into_iter() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize]
                [node.tree_position.left_job.index as usize]
                .get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize]
                [node.tree_position.right_job.index as usize]
                .get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok(job_ids)
}
