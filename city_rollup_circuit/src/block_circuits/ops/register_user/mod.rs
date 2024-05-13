use city_common::config::rollup_constants::GLOBAL_USER_TREE_HEIGHT;
use city_common_circuit::builder::hash::core::CircuitBuilderHashCore;
use city_common_circuit::builder::pad_circuit::pad_circuit_degree;
use city_common_circuit::circuits::traits::qstandard::provable::QStandardCircuitProvable;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitWithDefault;
use city_common_circuit::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;
use city_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use city_common_circuit::treeprover::wrapper::TreeProverLeafCircuitWrapper;
use city_crypto::hash::merkle::core::DeltaMerkleProofCore;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::hash::traits::hasher::MerkleZeroHasher;
use city_rollup_common::qworker::job_witnesses::op::CRUserRegistrationCircuitInput;
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

#[derive(Debug)]
pub struct CRUserRegistrationCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for CRUserRegistrationCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> CRUserRegistrationCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_append_only_skip_left::<C::Hasher, C::F, D>(
                &mut builder,
                GLOBAL_USER_TREE_HEIGHT as usize,
            );

        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            delta_merkle_proof_gadget.old_root,
            delta_merkle_proof_gadget.new_root,
        );
        let allowed_circuit_hashes_root_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_root_target.elements);
        builder.register_public_inputs(&state_transition_hash.elements);
        /*
        let x = builder.constant(C::F::ONE);
        let y = builder.constant(C::F::ZERO);
        let is_geq = builder.is_greater_than(32, x, y);
        builder.connect(is_geq.target, x);
        */
        pad_circuit_degree::<C::F, D>(&mut builder, 13);
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

impl<C: GenericConfig<D>, const D: usize> QStandardCircuitWithDefault
    for CRUserRegistrationCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn new_default(_network_magic: u64) -> Self {
        CRUserRegistrationCircuit::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for CRUserRegistrationCircuit<C, D>
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
    QStandardCircuitProvable<CRUserRegistrationCircuitInput<C::F>, C, D>
    for CRUserRegistrationCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &CRUserRegistrationCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        Ok(self.prove_base(
            &input.user_tree_delta_merkle_proof,
            input.allowed_circuit_hashes_root,
        ))
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRUserRegistrationCircuitInput<C::F>, C, D>
    for CRUserRegistrationCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &CRUserRegistrationCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

pub type WCRUserRegistrationCircuit<C, const D: usize> =
    TreeProverLeafCircuitWrapper<CRUserRegistrationCircuit<C, D>, C, D>;
