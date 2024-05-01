use core::fmt::Debug;
use plonky2::{
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::Serialize;
use std::{marker::PhantomData, sync::Mutex};
pub trait QStandardCircuit<C: GenericConfig<D>, const D: usize> {
    fn get_fingerprint(&self) -> QHashOut<C::F>;
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D>;
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D>;
    fn print_config(&self) {
        println!(
            "constants_sigmas_cap_height: {}",
            self.get_verifier_config_ref().constants_sigmas_cap.height()
        );
        println!("common_data: {:?}", self.get_common_circuit_data_ref());
    }
}
pub trait QStandardCircuitProvable<I: Serialize + Clone, C: GenericConfig<D>, const D: usize>:
    QStandardCircuit<C, D>
{
    fn prove_standard(&self, input: &I) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
#[derive(Debug)]
pub struct QStandardCircuitProvableWrapped<
    const M: usize,
    IC: QStandardCircuitProvable<I, C, D>,
    I: Serialize + Clone,
    C: GenericConfig<D> + 'static,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub circuit: IC,
    pub minifier: OASProofMinifierChain<D, C::F, C>,
    _phantom_i: PhantomData<I>,
}
impl<
        const M: usize,
        IC: QStandardCircuitProvable<I, C, D>,
        I: Serialize + Clone,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWrapped<M, IC, I, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_wrapped(inner_circuit: IC) -> Self {
        let minifier = OASProofMinifierChain::new(
            inner_circuit.get_verifier_config_ref(),
            inner_circuit.get_common_circuit_data_ref(),
            M,
        );
        Self {
            circuit: inner_circuit,
            minifier,
            _phantom_i: PhantomData,
        }
    }
}
impl<
        const M: usize,
        IC: QStandardCircuitProvable<I, C, D> + Clone,
        I: Serialize + Clone,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > Clone for QStandardCircuitProvableWrapped<M, IC, I, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new_wrapped(self.circuit.clone())
    }
}
impl<
        const M: usize,
        IC: QStandardCircuitProvable<I, C, D>,
        I: Serialize + Clone,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuit<C, D> for QStandardCircuitProvableWrapped<M, IC, I, C, D>
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
impl<
        const M: usize,
        IC: QStandardCircuitProvable<I, C, D>,
        I: Serialize + Clone,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvable<I, C, D> for QStandardCircuitProvableWrapped<M, IC, I, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_standard(&self, input: &I) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let inner_proof = self.circuit.prove_standard(input)?;
        self.minifier.prove(&inner_proof)
    }
}
use crate::common::{proof_minifier::pm_chain::OASProofMinifierChain, QHashOut};
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VerifierConfig<C: GenericConfig<D>, const D: usize> {
    pub common: CommonCircuitData<C::F, D>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
}

pub trait TreeProverLeafCircuit<
    I: Serialize + Clone + Debug + Send,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuitProvable<I, C, D> + Clone + Send
{
}
impl<
        SC: QStandardCircuitProvable<I, C, D> + Clone + Send,
        I: Serialize + Clone + Debug + Send,
        C: GenericConfig<D>,
        const D: usize,
    > TreeProverLeafCircuit<I, C, D> for SC
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
pub trait TPLeafAggregator<IL, IO> {
    fn get_output_from_inputs(left: &IO, right: &IO) -> IO;
    fn get_output_from_left_leaf(left: &IL, right: &IO) -> IO;
    fn get_output_from_right_leaf(left: &IO, right: &IL) -> IO;
    fn get_output_from_leaves(left: &IL, right: &IL) -> IO;
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
