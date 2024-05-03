use std::marker::PhantomData;

use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::{AlgebraicHasher, GenericConfig},
    proof::ProofWithPublicInputs,
};
use serde::Serialize;

use crate::proof_minifier::pm_chain::OASProofMinifierChain;

use super::QStandardCircuit;

pub trait QStandardCircuitProvable<I: Serialize + Clone, C: GenericConfig<D>, const D: usize>:
    QStandardCircuit<C, D>
{
    fn prove_standard(&self, input: &I) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

/*
impl<
        P: QStandardCircuitProvable<I, C, D>,
        S: QProofStoreReaderSync,
        I: Serialize + Clone,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreSync<S, I, C, D> for P
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &I,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

*/

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
