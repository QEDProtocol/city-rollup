use city_crypto::hash::{
    merkle::treeprover::DummyAggStateTransitionWithEvents, qhashout::QHashOut,
};
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::pad_circuit_degree},
    circuits::traits::qstandard::{
        provable::QStandardCircuitProvable, QStandardCircuit,
        QStandardCircuitProvableWithProofStoreSync,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};

#[derive(Debug)]
pub struct AggStateTransitionWithEventsDummyCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub state_transition_hash: HashOutTarget,
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub event_transition_hash: HashOutTarget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    //pub minifier_chain: QEDProofMinifierChain<D, C::F, C>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for AggStateTransitionWithEventsDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionWithEventsDummyCircuit<C, D>
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

        pad_circuit_degree::<C::F, D>(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        /*
        let minifier_chain =
            QEDProofMinifierChain::new(&circuit_data.verifier_only, &circuit_data.common, 1);*/
        Self {
            state_transition_hash,
            allowed_circuit_hashes_root,
            event_transition_hash,
            circuit_data,
            fingerprint,
            //minifier_chain,
        }
    }
    pub fn prove_base(
        &self,
        state_transition_hash: QHashOut<C::F>,
        allowed_circuit_hashes_root: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        //tracing::info!("agg_fingerprint: {}", agg_fingerprint.to_string());
        //tracing::info!("leaf_fingerprint: {}", leaf_fingerprint.to_string());
        pw.set_hash_target(self.state_transition_hash, state_transition_hash.0);
        pw.set_hash_target(
            self.allowed_circuit_hashes_root,
            allowed_circuit_hashes_root.0,
        );
        /*
        let inner_proof = self.circuit_data.prove(pw)?;

        self.minifier_chain.prove(&inner_proof)*/
        self.circuit_data.prove(pw)
    }
}

/*
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
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
*/
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
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

impl<C: GenericConfig<D>, const D: usize>
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

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
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
