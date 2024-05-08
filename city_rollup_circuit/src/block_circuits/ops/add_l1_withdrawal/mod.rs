use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use city_common_circuit::circuits::zk_signature_wrapper::ZKSignatureWrapperCircuit;
use city_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use city_common_circuit::treeprover::aggregation::state_transition_track_events::AggStateTrackableWithEventsInput;
use city_common_circuit::treeprover::aggregation::state_transition_track_events::StateTransitionWithEvents;
use city_common_circuit::treeprover::wrapper::TreeProverLeafCircuitWrapper;
use city_crypto::hash::merkle::core::DeltaMerkleProofCore;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::hash::traits::hasher::MerkleZeroHasher;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use serde::Deserialize;
use serde::Serialize;

use crate::state::user::add_l1_withdrawal::AddL1WithdrawalSingleGadget;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRAddL1WithdrawalCircuitInput<F: RichField> {
    pub user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub withdrawal_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
    pub signature_proof_id: QProvingJobDataID,
}
impl<F: RichField> AggStateTrackableWithEventsInput<F> for CRAddL1WithdrawalCircuitInput<F> {
    fn get_state_transition_with_events(&self) -> StateTransitionWithEvents<F> {
        StateTransitionWithEvents {
            state_transition_start: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.old_root.0,
                self.withdrawal_tree_delta_merkle_proof.old_root.0,
            )),
            state_transition_end: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.new_root.0,
                self.withdrawal_tree_delta_merkle_proof.new_root.0,
            )),
            event_hash: self.withdrawal_tree_delta_merkle_proof.new_value,
        }
    }
}

#[derive(Debug)]
pub struct CRAddL1WithdrawalCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub withdrawal_single_gadget: AddL1WithdrawalSingleGadget,
    pub signature_proof_target: ProofWithPublicInputsTarget<D>,

    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub network_magic: u64,

    // start dependencies
    pub signature_circuit_common_data: CommonCircuitData<C::F, D>,
    pub signature_circuit_verifier_data: VerifierOnlyCircuitData<C, D>,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone for CRAddL1WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new_with_signature_circuit_data(
            self.network_magic,
            self.signature_circuit_common_data.clone(),
            self.signature_circuit_verifier_data.clone(),
        )
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRAddL1WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(network_magic: u64) -> Self {
        let zk_signature_wrapper_circuit_data =
            ZKSignatureWrapperCircuit::<C, D>::new().circuit_data;

        Self::new_with_signature_circuit_data(
            network_magic,
            zk_signature_wrapper_circuit_data.common,
            zk_signature_wrapper_circuit_data.verifier_only,
        )
    }
    pub fn new_with_signature_circuit_data(
        network_magic: u64,
        signature_circuit_common_data: CommonCircuitData<C::F, D>,
        signature_circuit_verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let withdrawal_single_gadget = AddL1WithdrawalSingleGadget::add_virtual_to::<
            C::Hasher,
            C::F,
            D,
        >(&mut builder, network_magic);
        let expected_signature_combined_hash = withdrawal_single_gadget.expected_signature_hash;

        let signature_proof_target =
            builder.add_virtual_proof_with_pis(&signature_circuit_common_data);
        let signature_verifier_data_target =
            builder.constant_verifier_data(&signature_circuit_verifier_data);

        let signature_proof_combined_hash = HashOutTarget {
            elements: [
                signature_proof_target.public_inputs[0],
                signature_proof_target.public_inputs[1],
                signature_proof_target.public_inputs[2],
                signature_proof_target.public_inputs[3],
            ],
        };

        // ensure the claim is signed with the correct public key for L1 deposit
        builder.connect_hashes(
            signature_proof_combined_hash,
            expected_signature_combined_hash,
        );

        // verify the signature proof
        builder.verify_proof::<C>(
            &signature_proof_target,
            &signature_verifier_data_target,
            &signature_circuit_common_data,
        );

        let allowed_circuit_hashes_root_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_root_target.elements);
        builder.register_public_inputs(
            &withdrawal_single_gadget
                .combined_state_transition_hash
                .elements,
        );

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            withdrawal_single_gadget,
            signature_proof_target,
            allowed_circuit_hashes_root_target,
            circuit_data,
            fingerprint,
            network_magic,
            signature_circuit_common_data,
            signature_circuit_verifier_data,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRAddL1WithdrawalCircuitInput<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        self.withdrawal_single_gadget.withdrawal_gadget.set_witness(
            &mut pw,
            &input.withdrawal_tree_delta_merkle_proof,
            &input.user_tree_delta_merkle_proof,
        );

        pw.set_proof_with_pis_target(&self.signature_proof_target, signature_proof);

        pw.set_hash_target(
            self.allowed_circuit_hashes_root_target,
            input.allowed_circuit_hashes_root.0,
        );

        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRAddL1WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
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

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRAddL1WithdrawalCircuitInput<C::F>, C, D>
    for CRAddL1WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &CRAddL1WithdrawalCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let signature_proof = store.get_proof_by_id(input.signature_proof_id)?;
        self.prove_base(input, &signature_proof)
    }
}

pub type WCRAddL1WithdrawalCircuit<C, const D: usize> =
    TreeProverLeafCircuitWrapper<CRAddL1WithdrawalCircuit<C, D>, C, D>;
