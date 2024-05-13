use city_crypto::hash::merkle::treeprover::DummyAggStateTransitionWithEvents;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::pad_circuit_degree},
    circuits::traits::qstandard::{
        provable::QStandardCircuitProvable, QStandardCircuit,
        QStandardCircuitProvableWithProofStoreSync,
    },
    proof_minifier::{
        pm_chain_dynamic::OASProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic,
    },
};

#[derive(Debug)]
pub struct AggStateTransitionWithEventsDummyCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub state_transition_hash: HashOutTarget,
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub event_transition_hash: HashOutTarget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub minifier_chain: OASProofMinifierDynamicChain<D, C::F, C>,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone
    for AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let state_transition_hash = builder.add_virtual_hash();
        let allowed_circuit_hashes_root = builder.add_virtual_hash();
        let event_transition_hash = builder.constant_hash(HashOut::ZERO); //builder.add_virtual_hash();

        let transition =
            builder.hash_two_to_one::<C::Hasher>(state_transition_hash, state_transition_hash);

        builder.register_public_inputs(&allowed_circuit_hashes_root.elements);
        builder.register_public_inputs(&transition.elements);
        builder.register_public_inputs(&event_transition_hash.elements);

        pad_circuit_degree::<C::F, D>(&mut builder, 13);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        let minifier_chain =
            OASProofMinifierDynamicChain::new(&circuit_data.verifier_only, &circuit_data.common, 1);
        Self {
            state_transition_hash,
            allowed_circuit_hashes_root,
            event_transition_hash,
            circuit_data,
            fingerprint,
            minifier_chain,
        }
    }
    pub fn prove_base(
        &self,
        state_transition_hash: QHashOut<C::F>,
        allowed_circuit_hashes_root: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        //println!("agg_fingerprint: {}", agg_fingerprint.to_string());
        //println!("leaf_fingerprint: {}", leaf_fingerprint.to_string());
        pw.set_hash_target(self.state_transition_hash, state_transition_hash.0);
        pw.set_hash_target(
            self.allowed_circuit_hashes_root,
            allowed_circuit_hashes_root.0,
        );

        let inner_proof = self.circuit_data.prove(pw)?;

        self.minifier_chain.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
/*
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}
*/
impl<C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvable<DummyAggStateTransitionWithEvents<C::F>, C, D>
    for AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_standard(
        &self,
        input: &DummyAggStateTransitionWithEvents<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(
            input.state_transition_hash,
            input.allowed_circuit_hashes_root,
        )
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, DummyAggStateTransitionWithEvents<C::F>, C, D>
    for AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &DummyAggStateTransitionWithEvents<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
