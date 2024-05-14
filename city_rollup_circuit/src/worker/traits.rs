use city_common_circuit::{
    circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync,
    treeprover::traits::TreeProverAggCircuit,
};
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID, job_witnesses::op::CircuitInputWithDependencies,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
};
use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

pub trait QWorkerGenericProver<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>:
    QWorkerVerifyHelper<C, D>
{
    fn worker_prove(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QWorkerGenericProverMut<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>:
    QWorkerVerifyHelper<C, D>
{
    fn worker_prove_mut(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QWorkerCircuitSimpleWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_simple(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QWorkerCircuitAggWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_agg(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

pub trait QWorkerCircuitCustomWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_custom(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QWorkerCircuitMutCustomWithDataSync<
    S: QProofStoreReaderSync,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_mut_custom(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
impl<
        SCP: QStandardCircuitProvableWithProofStoreSync<S, I, C, D>,
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        I: DeserializeOwned + Serialize + Clone, // the type parameter `I` is not constrained by the impl trait, self type, or predicates
        C: GenericConfig<D>,
        const D: usize,
    > QWorkerCircuitSimpleWithDataSync<V, S, I, C, D> for SCP
{
    fn prove_q_worker_simple(
        &self,
        _verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let witness_data = store.get_bytes_by_id(job_id)?;
        let input = bincode::deserialize(&witness_data)?;
        self.prove_with_proof_store_sync(store, &input)
    }
}

impl<
        TC: TreeProverAggCircuit<I, C, D>,
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D>,
        I: DeserializeOwned + Serialize + Clone + Send + Debug + PartialEq,
        const D: usize,
    > QWorkerCircuitAggWithDataSync<V, S, I, C, D> for TC
{
    fn prove_q_worker_agg(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_data = store.get_bytes_by_id(job_id)?;
        let input = bincode::deserialize::<CircuitInputWithDependencies<I>>(&input_data)?;

        if input.dependencies.len() == 2 {
            let fingerprint_config =
                verify_helper.get_tree_prover_fingerprint_config(job_id.circuit_type)?;
            let (_, leaf_verifier_data, _) = verify_helper.get_verifier_triplet_for_circuit_type(
                fingerprint_config.leaf_circuit_type.try_into()?,
            );
            /*
            let (left_child_verifier_data, left_child_common_data, left_child_fingerprint) =
                verify_helper
                    .get_verifier_triplet_for_circuit_type(input.dependencies[0].circuit_type);
            let (right_child_verifier_data, right_child_common_data, right_child_fingerprint) =
                verify_helper
                    .get_verifier_triplet_for_circuit_type(input.dependencies[1].circuit_type);
            */
            let left_proof = store.get_proof_by_id(input.dependencies[0])?;
            let right_proof = store.get_proof_by_id(input.dependencies[1])?;

            self.prove_full(
                fingerprint_config.aggregator_fingerprint,
                self.get_verifier_config_ref(),
                fingerprint_config.leaf_fingerprint,
                leaf_verifier_data,
                &left_proof,
                &right_proof,
                &input.input,
            )
        } else {
            anyhow::bail!("aggregation proving jobs must have two dependency proofs to recursively verify, got {}",input.dependencies.len());
        }
    }
}
