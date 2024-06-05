use city_common_circuit::{
    builder::{
        pad_circuit::CircuitBuilderCityCommonGates, verify::CircuitBuilderVerifyProofHelpers,
    },
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};
use city_crypto::hash::{qhashout::QHashOut, traits::hasher::MerkleZeroHasher};

use city_rollup_common::qworker::{
    job_id::QProvingJobDataID, job_witnesses::op::CRAddL1WithdrawalCircuitInput,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    state::user::add_l1_withdrawal::AddL1WithdrawalSingleGadget,
    worker::traits::QWorkerCircuitStandardWithDataSync,
};

#[derive(Debug)]
pub struct CRAddL1WithdrawalCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub withdrawal_single_gadget: AddL1WithdrawalSingleGadget,
    pub signature_proof_target: ProofWithPublicInputsTarget<D>,
    pub signature_verifier_data_target: VerifierCircuitTarget,

    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub network_magic: u64,
    // start dependencies
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRAddL1WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new_with_signature_circuit_data(
        network_magic: u64,
        signature_circuit_common_data: &CommonCircuitData<C::F, D>,
        signature_circuit_verifier_data_cap_height: usize,
        signature_wrapper_fingerprint: QHashOut<C::F>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let withdrawal_single_gadget = AddL1WithdrawalSingleGadget::add_virtual_to::<
            C::Hasher,
            C::F,
            D,
        >(&mut builder, network_magic);
        let expected_signature_combined_hash = withdrawal_single_gadget.expected_signature_hash;
        let expected_signature_public_key = withdrawal_single_gadget.expected_public_key;

        let signature_proof_target =
            builder.add_virtual_proof_with_pis(&signature_circuit_common_data);
        let signature_verifier_data_target =
            builder.add_virtual_verifier_data(signature_circuit_verifier_data_cap_height);

        let signature_proof_public_key = HashOutTarget {
            elements: [
                signature_proof_target.public_inputs[0],
                signature_proof_target.public_inputs[1],
                signature_proof_target.public_inputs[2],
                signature_proof_target.public_inputs[3],
            ],
        };

        let signature_proof_combined_hash = HashOutTarget {
            elements: [
                signature_proof_target.public_inputs[4],
                signature_proof_target.public_inputs[5],
                signature_proof_target.public_inputs[6],
                signature_proof_target.public_inputs[7],
            ],
        };
        
        // ensure the claim is signed with the correct public key for L1 deposit
        builder.connect_hashes(
            signature_proof_public_key,
            expected_signature_public_key,
        );
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

        let actual_sig_wrapper_fingerprint =
            builder.get_circuit_fingerprint::<C::Hasher>(&signature_verifier_data_target);
        let expected_sig_wrapper_fingerprint =
            builder.constant_hash(signature_wrapper_fingerprint.0);
        builder.connect_hashes(
            actual_sig_wrapper_fingerprint,
            expected_sig_wrapper_fingerprint,
        );
        let allowed_circuit_hashes_root_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_root_target.elements);
        builder.register_public_inputs(
            &withdrawal_single_gadget
                .combined_state_transition_hash
                .elements,
        );

        builder.add_city_common_gates(None);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            withdrawal_single_gadget,
            signature_proof_target,
            allowed_circuit_hashes_root_target,
            circuit_data,
            fingerprint,
            network_magic,
            signature_verifier_data_target,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRAddL1WithdrawalCircuitInput<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
        signature_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        self.withdrawal_single_gadget.withdrawal_gadget.set_witness(
            &mut pw,
            &input.withdrawal_tree_delta_merkle_proof,
            &input.user_tree_delta_merkle_proof,
        );
        println!("CRAddL1WithdrawalCircuitInput: {:?}",input);
        println!("signature_proof.public_inputs: {:?}",signature_proof.public_inputs);
        pw.set_proof_with_pis_target(&self.signature_proof_target, signature_proof);
        pw.set_verifier_data_target(
            &self.signature_verifier_data_target,
            signature_verifier_data,
        );

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
impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitStandardWithDataSync<V, S, CRAddL1WithdrawalCircuitInput<C::F>, C, D>
    for CRAddL1WithdrawalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_q_worker_standard_with_input(
        &self,
        input: &CRAddL1WithdrawalCircuitInput<C::F>,
        verify_helper: &V,
        store: &S,
        _job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let signature_proof = store.get_proof_by_id(input.signature_proof_id)?;
        self.prove_base(
            input,
            &signature_proof,
            verify_helper
                .get_verifier_triplet_for_circuit_type(input.signature_proof_id.circuit_type)
                .1,
        )
    }
}
