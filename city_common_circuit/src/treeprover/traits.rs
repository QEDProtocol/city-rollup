use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use core::fmt::Debug;
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::{AlgebraicHasher, GenericConfig},
    proof::ProofWithPublicInputs,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    circuits::traits::qstandard::{QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_chain::OASProofMinifierChain,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VerifierConfig<C: GenericConfig<D>, const D: usize> {
    pub common: CommonCircuitData<C::F, D>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
}

pub trait TreeProverLeafCircuit<
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone + Debug + Send,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuitProvableWithProofStoreSync<S, I, C, D> + Clone + Send
{
}
impl<
        SC: QStandardCircuitProvableWithProofStoreSync<S, I, C, D> + Clone + Send,
        S: QProofStoreReaderSync,
        I: DeserializeOwned + Serialize + Clone + Debug + Send,
        C: GenericConfig<D>,
        const D: usize,
    > TreeProverLeafCircuit<S, I, C, D> for SC
{
}

pub struct TreeAggInput<IO: Serialize + Clone + Debug, C: GenericConfig<D>, const D: usize> {
    pub proof_left: ProofWithPublicInputs<C::F, C, D>,
    pub proof_right: ProofWithPublicInputs<C::F, C, D>,
    pub input: IO,
}
pub struct TreeProverAggCircuitWrapper<AC, C: 'static + GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub circuit: AC,
    pub minifier: OASProofMinifierChain<D, C::F, C>,
}
impl<AC: QStandardCircuit<C, D> + Clone, C: 'static + GenericConfig<D>, const D: usize> Clone
    for TreeProverAggCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        let circuit = self.circuit.clone();
        let minifier = OASProofMinifierChain::new(
            circuit.get_verifier_config_ref(),
            circuit.get_common_circuit_data_ref(),
            self.minifier.minifiers.len(),
        );
        Self { circuit, minifier }
    }
}
impl<AC: QStandardCircuit<C, D>, C: 'static + GenericConfig<D>, const D: usize>
    QStandardCircuit<C, D> for TreeProverAggCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier.get_common_data()
    }
}

/*
impl<
        AC: TreeProverAggCircuit<IL, IO, C, D>,
        C: 'static + GenericConfig<D>,
        IL: Serialize + Clone + Debug + Send,
        IO: Serialize + Clone + Debug + Send,
        const D: usize,
    > TPLeafAggregator<IL, IO> for TreeProverAggCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_output_from_inputs(&self, left: &IO, right: &IO) -> IO {
        self.circuit.get_output_from_inputs(left, right)
    }

    fn get_output_from_left_leaf(&self, left: &IL, right: &IO) -> IO {
        self.circuit.get_output_from_left_leaf(left, right)
    }

    fn get_output_from_right_leaf(&self, left: &IO, right: &IL) -> IO {
        self.circuit.get_output_from_right_leaf(left, right)
    }

    fn get_output_from_leaves(&self, left: &IL, right: &IL) -> IO {
        self.circuit.get_output_from_leaves(left, right)
    }
}
*/
impl<
        AC: TreeProverAggCircuit<IO, C, D>,
        C: 'static + GenericConfig<D>,
        IO: Serialize + Clone + Debug + Send,
        const D: usize,
    > TreeProverAggCircuit<IO, C, D> for TreeProverAggCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn new(child_common_data: &CommonCircuitData<C::F, D>, verifier_cap_height: usize) -> Self {
        let circuit = AC::new(child_common_data, verifier_cap_height);
        let minifier = OASProofMinifierChain::new(
            circuit.get_verifier_config_ref(),
            circuit.get_common_circuit_data_ref(),
            1,
        );
        Self { circuit, minifier }
    }

    fn prove_full(
        &self,
        agg_fingerprint: QHashOut<C::F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<C::F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        input: &IO,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let inner_proof = self.circuit.prove_full(
            agg_fingerprint,
            agg_verifier_data,
            leaf_fingerprint,
            leaf_verifier_data,
            left_proof,
            right_proof,
            input,
        )?;
        self.minifier.prove(&inner_proof)
    }
}
pub trait TreeProverAggCircuit<
    IO: Serialize + Clone + Debug + Send,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D> + Clone + Send
{
    fn new(child_common_data: &CommonCircuitData<C::F, D>, verifier_cap_height: usize) -> Self;
    fn prove_full(
        &self,
        agg_fingerprint: QHashOut<C::F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<C::F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        input: &IO,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn prove(
        &self,
        leaf_fingerprint: QHashOut<C::F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        input: &IO,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let agg_fingerprint = self.get_fingerprint();
        let agg_verifier_data = self.get_verifier_config_ref();
        self.prove_full(
            agg_fingerprint,
            agg_verifier_data,
            leaf_fingerprint,
            leaf_verifier_data,
            left_proof,
            right_proof,
            input,
        )
    }
}
