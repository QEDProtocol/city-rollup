use city_common_circuit::{
    builder::{pad_circuit::pad_circuit_degree, verify::CircuitBuilderVerifyProofHelpers},
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::wrapper::TreeProverLeafCircuitWrapper,
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID, job_witnesses::op::CRClaimL1DepositCircuitInput,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
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
    state::user::claim_l1_deposit::ClaimL1DepositSingleGadget,
    worker::traits::QWorkerCircuitStandardWithDataSync,
};

#[derive(Debug)]
pub struct CRClaimL1DepositCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub claim_single_gadget: ClaimL1DepositSingleGadget,
    pub signature_proof_target: ProofWithPublicInputsTarget<D>,
    pub signature_verifier_data_target: VerifierCircuitTarget,

    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub network_magic: u64,
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRClaimL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_with_signature_circuit_data(
        network_magic: u64,
        signature_circuit_common_data: &CommonCircuitData<C::F, D>,
        signature_circuit_verifier_data_cap_height: usize,
        signature_wrapper_fingerprint: QHashOut<C::F>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let claim_single_gadget = ClaimL1DepositSingleGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            network_magic,
        );
        let expected_signature_combined_hash =
            claim_single_gadget.signature_combo_gadget.combined_hash;

        let signature_proof_target =
            builder.add_virtual_proof_with_pis(&signature_circuit_common_data);

        let signature_verifier_data_target =
            builder.add_virtual_verifier_data(signature_circuit_verifier_data_cap_height);
        let expected_sig_fingerprint = builder.constant_hash(signature_wrapper_fingerprint.0);
        let computed_sig_fingerprint =
            builder.get_circuit_fingerprint::<C::Hasher>(&signature_verifier_data_target);

        builder.connect_hashes(computed_sig_fingerprint, expected_sig_fingerprint);

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
        builder
            .register_public_inputs(&claim_single_gadget.combined_state_transition_hash.elements);
        pad_circuit_degree::<C::F, D>(&mut builder, 12);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            claim_single_gadget,
            signature_proof_target,
            signature_verifier_data_target,
            allowed_circuit_hashes_root_target,
            circuit_data,
            fingerprint,
            network_magic,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRClaimL1DepositCircuitInput<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
        signature_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        self.claim_single_gadget.claim_gadget.set_witness(
            &mut pw,
            &input.deposit,
            &input.deposit_tree_delta_merkle_proof,
            &input.user_tree_delta_merkle_proof,
        );

        pw.set_proof_with_pis_target(&self.signature_proof_target, signature_proof);
        pw.set_verifier_data_target(
            &self.signature_verifier_data_target,
            &signature_verifier_data,
        );
        pw.set_hash_target(
            self.allowed_circuit_hashes_root_target,
            input.allowed_circuit_hashes_root.0,
        );

        let result = self.circuit_data.prove(pw)?;

        Ok(result)
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRClaimL1DepositCircuit<C, D>
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
impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitStandardWithDataSync<V, S, CRClaimL1DepositCircuitInput<C::F>, C, D>
    for CRClaimL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_q_worker_standard_with_input(
        &self,
        input: &CRClaimL1DepositCircuitInput<C::F>,
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

pub type WCRClaimL1DepositCircuit<C, const D: usize> =
    TreeProverLeafCircuitWrapper<CRClaimL1DepositCircuit<C, D>, C, D>;
