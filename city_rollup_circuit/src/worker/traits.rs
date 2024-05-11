use city_common_circuit::{
    circuits::traits::qstandard::{QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    treeprover::{
        aggregation::state_transition::AggStateTransitionCircuit, traits::TreeProverAggCircuit,
    },
};
use city_crypto::hash::{merkle::treeprover::AggStateTransitionInput, qhashout::QHashOut};
use city_rollup_common::qworker::{
    job_id::{ProvingJobCircuitType, QProvingJobDataID},
    proof_store::QProofStoreReaderSync,
    verifier::QWorkerVerifyHelper,
};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::{AlgebraicHasher, GenericConfig},
    proof::ProofWithPublicInputs,
};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;

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
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let witness_data = store.get_bytes_by_id(job_id)?;
        let input = bincode::deserialize(&witness_data)?;
        self.prove_with_proof_store_sync(store, &input)
    }
}
