use city_common::tree_planner::{BinaryTreeJob, BinaryTreePlanner};
use city_crypto::hash::merkle::treeprover::TPLeafAggregator;
use city_rollup_common::qworker::proof_store::{QProofStoreReaderSync, QProofStoreWriterSync};
use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};
use serde::{de::DeserializeOwned, Serialize};
use core::fmt::Debug;

use super::traits::{TreeProverAggCircuit, TreeProverLeafCircuit};

#[derive(Debug, Clone, Serialize)]
pub struct TreeAggJob<IO: Serialize + Clone + Debug + Send> {
    pub input: IO,
    pub tree_position: BinaryTreeJob,
}
impl<IO: Serialize + Clone + Debug + Send> TreeAggJob<IO> {
    pub fn new(input: IO, tree_position: BinaryTreeJob) -> Self {
        Self {
            input,
            tree_position,
        }
    }
}

pub fn generate_agg_jobs<
    LA: TPLeafAggregator<IL, IO>,
    IL: DeserializeOwned + Serialize + Clone + Debug + Send,
    IO: DeserializeOwned + Serialize + Clone + Debug + Send,
>(
    leaf_inputs: &[IL],
) -> Vec<Vec<TreeAggJob<IO>>> {
    let tree_positions = BinaryTreePlanner::new(leaf_inputs.len()).levels;
    println!(
        "tree_positions = {}",
        serde_json::to_string(&tree_positions).unwrap()
    );
    let mut output: Vec<Vec<TreeAggJob<IO>>> = Vec::with_capacity(tree_positions.len());
    for level in tree_positions {
        println!("output.len() = {}", output.len());
        let mut level_output: Vec<TreeAggJob<IO>> = Vec::with_capacity(level.len());
        for job in level {
            println!("job: {:?}", job);
            let input = if job.left_job.is_leaf() {
                if job.right_job.is_leaf() {
                    LA::get_output_from_leaves(
                        &leaf_inputs[job.left_job.index as usize],
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_left_leaf(
                        &leaf_inputs[job.left_job.index as usize],
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize]
                            .input,
                    )
                }
            } else {
                if job.right_job.is_leaf() {
                    LA::get_output_from_right_leaf(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize].input,
                        &leaf_inputs[job.right_job.index as usize],
                    )
                } else {
                    LA::get_output_from_inputs(
                        &output[job.left_job.level as usize - 1][job.left_job.index as usize].input,
                        &output[job.right_job.level as usize - 1][job.right_job.index as usize]
                            .input,
                    )
                }
            };
            level_output.push(TreeAggJob {
                input,
                tree_position: job,
            });
        }
        output.push(level_output);
    }

    output
}
pub fn prove_tree_serial<
    S: QProofStoreReaderSync + QProofStoreWriterSync,
    LA: TPLeafAggregator<IL, IO>,
    AC: TreeProverAggCircuit<IO, C, D>,
    LC: TreeProverLeafCircuit<S, IL, C, D>,
    IL: DeserializeOwned + Serialize + Clone + Debug + Send,
    IO: DeserializeOwned + Serialize + Clone + Debug + Send,
    C: GenericConfig<D>,
    const D: usize,
>(
    store: S,
    leaf_circuit: LC,
    agg_circuit: AC,
    leaf_inputs: Vec<IL>,
) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
    if leaf_inputs.len() == 1 {
        return leaf_circuit.prove_with_proof_store_sync(&store, &leaf_inputs[0]);
    }

    let leaf_fingerprint = leaf_circuit.get_fingerprint();
    let leaf_verifier_data = leaf_circuit.get_verifier_config_ref().clone();
    let job_plan = generate_agg_jobs::<LA, IL, IO>(&leaf_inputs);

    let leaf_proofs = leaf_inputs
        .iter()
        .map(|input| leaf_circuit.prove_with_proof_store_sync(&store, &input))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut current_proofs = vec![leaf_proofs];
    for level in job_plan {
        let mut level_proofs = Vec::with_capacity(level.len());
        for job in level {
            let left_proof = &current_proofs[job.tree_position.left_job.level as usize]
                [job.tree_position.left_job.index as usize];
            let right_proof = &current_proofs[job.tree_position.right_job.level as usize]
                [job.tree_position.right_job.index as usize];
            let proof = agg_circuit.prove(
                leaf_fingerprint,
                &leaf_verifier_data,
                &left_proof,
                &right_proof,
                &job.input,
            )?;
            println!(
                "proved agg: {}, {}",
                current_proofs.len(),
                level_proofs.len()
            );
            level_proofs.push(proof);
        }
        current_proofs.push(level_proofs);
    }
    current_proofs
        .into_iter()
        .last()
        .unwrap()
        .into_iter()
        .last()
        .ok_or_else(|| anyhow::anyhow!("Failed to get the last proof"))
}
