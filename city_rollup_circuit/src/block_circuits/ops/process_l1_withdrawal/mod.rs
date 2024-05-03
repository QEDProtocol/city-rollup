use city_common::config::rollup_constants::L1_WITHDRAWAL_TREE_HEIGHT;
use city_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::{
        aggregation::state_transition_track_events::{
            AggStateTrackableWithEventsInput, StateTransitionWithEvents,
        },
        traits::{QStandardCircuit, QStandardCircuitProvable},
    },
};
use city_crypto::hash::{
    merkle::core::DeltaMerkleProofCore, qhashout::QHashOut, traits::hasher::MerkleZeroHasher,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRProcessL2WithdrawalCircuitInput<F: RichField> {
    pub withdrawal_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes: QHashOut<F>,
}

impl<F: RichField> AggStateTrackableWithEventsInput<F> for CRProcessL2WithdrawalCircuitInput<F> {
    fn get_state_transition_with_events(&self) -> StateTransitionWithEvents<F> {
        StateTransitionWithEvents {
            state_transition_start: self.withdrawal_tree_delta_merkle_proof.old_root,
            state_transition_end: self.withdrawal_tree_delta_merkle_proof.new_root,
            event_hash: self.withdrawal_tree_delta_merkle_proof.new_value,
        }
    }
}

#[derive(Debug)]
pub struct CRProcessL2WithdrawalCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub allowed_circuit_hashes_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for CRProcessL2WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> CRProcessL2WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_dequeue_left::<C::Hasher, C::F, D>(
                &mut builder,
                L1_WITHDRAWAL_TREE_HEIGHT as usize,
            );
        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            delta_merkle_proof_gadget.old_root,
            delta_merkle_proof_gadget.new_root,
        );

        let event_transition_hash = delta_merkle_proof_gadget.old_value;
        let allowed_circuit_hashes_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_target.elements);
        builder.register_public_inputs(&state_transition_hash.elements);
        builder.register_public_inputs(&event_transition_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            delta_merkle_proof_gadget,
            allowed_circuit_hashes_target,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        allowed_circuit_hashes: QHashOut<C::F>,
    ) -> ProofWithPublicInputs<C::F, C, D> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.allowed_circuit_hashes_target, allowed_circuit_hashes.0);
        self.delta_merkle_proof_gadget
            .set_witness_core_proof_q(&mut pw, &delta_merkle_proof);
        self.circuit_data.prove(pw).unwrap()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for CRProcessL2WithdrawalCircuit<C, D>
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
    QStandardCircuitProvable<CRProcessL2WithdrawalCircuitInput<C::F>, C, D>
    for CRProcessL2WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &CRProcessL2WithdrawalCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        Ok(self.prove_base(
            &input.withdrawal_tree_delta_merkle_proof,
            input.allowed_circuit_hashes,
        ))
    }
}
