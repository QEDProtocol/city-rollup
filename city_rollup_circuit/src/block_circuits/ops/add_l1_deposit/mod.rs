use city_common::config::rollup_constants::L1_DEPOSIT_TREE_HEIGHT;
use city_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderCityCommonGates},
    },
    circuits::traits::qstandard::{
        provable::QStandardCircuitProvable, QStandardCircuit,
        QStandardCircuitProvableWithProofStoreSync,
    },
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::wrapper::TreeProverLeafCircuitWrapper,
};
use city_crypto::hash::{
    merkle::core::DeltaMerkleProofCore, qhashout::QHashOut, traits::hasher::MerkleZeroHasher,
};
use city_rollup_common::qworker::{
    job_witnesses::op::CRAddL1DepositCircuitInput, proof_store::QProofStoreReaderSync,
};
use plonky2::{
    gates::gate::GateRef,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

#[derive(Debug)]
pub struct CRAddL1DepositCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> CRAddL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(coset_gate: &GateRef<C::F, D>) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_push_sparse_list::<C::Hasher, C::F, D>(
                &mut builder,
                L1_DEPOSIT_TREE_HEIGHT as usize,
            );
        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            delta_merkle_proof_gadget.old_root,
            delta_merkle_proof_gadget.new_root,
        );

        let event_transition_hash = delta_merkle_proof_gadget.new_value;

        let allowed_circuit_hashes_root_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_root_target.elements);
        builder.register_public_inputs(&state_transition_hash.elements);
        builder.register_public_inputs(&event_transition_hash.elements);

        pad_circuit_degree::<C::F, D>(&mut builder, 12);
        builder.add_city_common_gates(Some(coset_gate.clone()));

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            delta_merkle_proof_gadget,
            allowed_circuit_hashes_root_target,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        allowed_circuit_hashes_root: QHashOut<C::F>,
    ) -> ProofWithPublicInputs<C::F, C, D> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(
            self.allowed_circuit_hashes_root_target,
            allowed_circuit_hashes_root.0,
        );
        self.delta_merkle_proof_gadget
            .set_witness_core_proof_q(&mut pw, &delta_merkle_proof);
        self.circuit_data.prove(pw).unwrap()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for CRAddL1DepositCircuit<C, D>
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
    QStandardCircuitProvable<CRAddL1DepositCircuitInput<C::F>, C, D> for CRAddL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &CRAddL1DepositCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        Ok(self.prove_base(
            &input.deposit_tree_delta_merkle_proof,
            input.allowed_circuit_hashes_root,
        ))
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRAddL1DepositCircuitInput<C::F>, C, D>
    for CRAddL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &CRAddL1DepositCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

pub type WCRAddL1DepositCircuit<C, const D: usize> =
    TreeProverLeafCircuitWrapper<CRAddL1DepositCircuit<C, D>, C, D>;
