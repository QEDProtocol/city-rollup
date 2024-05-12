use std::fmt::Debug;

use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::circuits::traits::qstandard::QStandardCircuit;
use crate::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use crate::circuits::traits::qstandard::QStandardCircuitWithDefault;
use crate::circuits::traits::qstandard::QStandardCircuitWithDefaultMinified;
use crate::proof_minifier::pm_chain_dynamic::OASProofMinifierDynamicChain;

pub struct TreeProverLeafCircuitWrapper<AC, C: 'static + GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub circuit: AC,
    pub minifier: OASProofMinifierDynamicChain<D, C::F, C>,
    pub network_magic: u64,
}

impl<AC: QStandardCircuit<C, D>, C: 'static + GenericConfig<D>, const D: usize>
    TreeProverLeafCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(circuit: AC, network_magic: u64, n_minifiers: usize) -> Self {
        let minifier = OASProofMinifierDynamicChain::new(
            circuit.get_verifier_config_ref(),
            circuit.get_common_circuit_data_ref(),
            n_minifiers,
        );
        Self {
            circuit,
            minifier,
            network_magic,
        }
    }
}
impl<AC, C: 'static + GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for TreeProverLeafCircuitWrapper<AC, C, D>
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
        AC: QStandardCircuitWithDefault + QStandardCircuit<C, D>,
        C: 'static + GenericConfig<D>,
        const D: usize,
    > QStandardCircuitWithDefaultMinified for TreeProverLeafCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn new_default_with_minifiers(network_magic: u64, n_minifiers: usize) -> Self {
        let circuit = AC::new_default(network_magic);
        let minifier = OASProofMinifierDynamicChain::new(
            circuit.get_verifier_config_ref(),
            circuit.get_common_circuit_data_ref(),
            n_minifiers,
        );
        Self {
            circuit,
            minifier,
            network_magic,
        }
    }
}
impl<
        AC: QStandardCircuitWithDefault + QStandardCircuit<C, D>,
        C: 'static + GenericConfig<D>,
        const D: usize,
    > Clone for TreeProverLeafCircuitWrapper<AC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        let circuit = AC::new_default(self.network_magic);
        let minifier = OASProofMinifierDynamicChain::new(
            circuit.get_verifier_config_ref(),
            circuit.get_common_circuit_data_ref(),
            self.minifier.minifiers.len(),
        );
        Self {
            circuit,
            minifier,
            network_magic: self.network_magic,
        }
    }
}

impl<
        SC: QStandardCircuitProvableWithProofStoreSync<S, I, C, D> + Clone + Send,
        S: QProofStoreReaderSync,
        I: DeserializeOwned + Serialize + Clone + Debug + Send,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreSync<S, I, C, D>
    for TreeProverLeafCircuitWrapper<SC, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &I,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let base = self.circuit.prove_with_proof_store_sync(store, input)?;
        self.minifier.prove(&base)
    }
}
