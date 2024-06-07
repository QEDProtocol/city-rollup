use city_common_circuit::{
    builder::{
        core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore,
        pad_circuit::pad_circuit_degree, verify::CircuitBuilderVerifyProofHelpers,
    },
    circuits::{
        traits::qstandard::QStandardCircuit, zk_signature_wrapper::ZKSignatureWrapperCircuit,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::wrapper::TreeProverLeafCircuitWrapper,
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::{
    introspection::rollup::constants::SIG_ACTION_TRANSFER_MAGIC,
    qworker::{
        job_id::QProvingJobDataID, job_witnesses::op::CRL2TransferCircuitInput,
        proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
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
    introspection::gadgets::rollup::signature::compute_sig_action_hash_circuit,
    state::user::l2_transfer_state_update::L2TransferStateUpdateGadget,
    worker::traits::QWorkerCircuitStandardWithDataSync,
};

#[derive(Debug, Clone)]
pub struct L2TransferSingleGadget {
    // inputs:
    pub l2_transfer_gadget: L2TransferStateUpdateGadget,

    // computed:
    pub expected_signature_hash: HashOutTarget,
    pub expected_public_key: HashOutTarget,
    pub old_user_tree_root: HashOutTarget,
    pub new_user_tree_root: HashOutTarget,
}
impl L2TransferSingleGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        network_magic: u64,
    ) -> Self {
        let l2_transfer_gadget = L2TransferStateUpdateGadget::add_virtual_to::<H, F, D>(builder);
        let sig_action_id = builder.constant_u64(SIG_ACTION_TRANSFER_MAGIC);
        let network_magic_target = builder.constant_u64(network_magic);
        let sender_user_id = l2_transfer_gadget.sender_old_user_state.user_id;
        let recipient_user_id = l2_transfer_gadget.receiver_old_user_state.user_id;
        let new_sender_user_nonce = l2_transfer_gadget.sender_new_user_state.nonce;

        let amount = l2_transfer_gadget.transfer_amount;

        let expected_signature_hash = compute_sig_action_hash_circuit::<H, F, D>(
            builder,
            network_magic_target,
            sender_user_id,
            sig_action_id,
            new_sender_user_nonce,
            &[recipient_user_id, amount],
        );
        let expected_public_key = l2_transfer_gadget.sender_old_user_state.public_key;

        let old_user_tree_root = l2_transfer_gadget
            .sender_user_tree_delta_merkle_proof_gadget
            .old_root;
        let new_user_tree_root = l2_transfer_gadget
            .receiver_user_tree_delta_merkle_proof_gadget
            .new_root;

        Self {
            l2_transfer_gadget,
            expected_signature_hash,
            expected_public_key,
            old_user_tree_root,
            new_user_tree_root,
        }
    }
}

#[derive(Debug)]
pub struct CRL2TransferCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub l2_transfer_single_gadget: L2TransferSingleGadget,
    pub signature_proof_target: ProofWithPublicInputsTarget<D>,
    pub signature_verifier_data_target: VerifierCircuitTarget,

    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub network_magic: u64,
    // dependencies
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(network_magic: u64) -> Self {
        let sig_wrapper = ZKSignatureWrapperCircuit::<C, D>::new().circuit_data;

        Self::new_with_sig_wrapper_data(
            network_magic,
            &sig_wrapper.common,
            sig_wrapper.verifier_only.constants_sigmas_cap.height(),
            QHashOut(get_circuit_fingerprint_generic(&sig_wrapper.verifier_only)),
        )
    }
    pub fn new_with_sig_wrapper_data(
        network_magic: u64,
        signature_circuit_common_data: &CommonCircuitData<C::F, D>,
        signature_circuit_verifier_data_cap_height: usize,
        signature_wrapper_fingerprint: QHashOut<C::F>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let l2_transfer_single_gadget = L2TransferSingleGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            network_magic,
        );

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
        let signature_proof_message_hash = HashOutTarget {
            elements: [
                signature_proof_target.public_inputs[4],
                signature_proof_target.public_inputs[5],
                signature_proof_target.public_inputs[6],
                signature_proof_target.public_inputs[7],
            ],
        };

        // ensure the transaction is signed with the correct public key for the sender
        builder.connect_hashes(
            signature_proof_public_key,
            l2_transfer_single_gadget.expected_public_key,
        );

        // ensure the signature signs the correct message hash for this transfer
        builder.connect_hashes(
            signature_proof_message_hash,
            l2_transfer_single_gadget.expected_signature_hash,
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

        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            l2_transfer_single_gadget.old_user_tree_root,
            l2_transfer_single_gadget.new_user_tree_root,
        );

        builder.register_public_inputs(&allowed_circuit_hashes_root_target.elements);
        builder.register_public_inputs(&state_transition_hash.elements);

        pad_circuit_degree::<C::F, D>(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            l2_transfer_single_gadget,
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
        input: &CRL2TransferCircuitInput<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
        signature_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        println!("token_input: {:?}", input);
        println!("token_input: {}", serde_json::to_string(&input).unwrap());
        println!("signature_proof_public_inputs: {:?}",signature_proof.public_inputs);

        let mut pw = PartialWitness::new();
        self.l2_transfer_single_gadget
            .l2_transfer_gadget
            .set_witness(
                &mut pw,
                &input.sender_user_tree_delta_merkle_proof,
                &input.receiver_user_tree_delta_merkle_proof,
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

        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRL2TransferCircuit<C, D>
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
    > QWorkerCircuitStandardWithDataSync<V, S, CRL2TransferCircuitInput<C::F>, C, D>
    for CRL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_q_worker_standard_with_input(
        &self,
        input: &CRL2TransferCircuitInput<C::F>,
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

pub type WCRL2TransferCircuit<C, const D: usize> =
    TreeProverLeafCircuitWrapper<CRL2TransferCircuit<C, D>, C, D>;
