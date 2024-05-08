use city_common_circuit::builder::core::CircuitBuilderHelpersCore;
use city_common_circuit::builder::hash::core::CircuitBuilderHashCore;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use city_common_circuit::circuits::zk_signature_wrapper::ZKSignatureWrapperCircuit;
use city_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use city_common_circuit::treeprover::aggregation::state_transition::AggStateTrackableInput;
use city_common_circuit::treeprover::aggregation::state_transition::AggStateTransition;
use city_common_circuit::treeprover::wrapper::TreeProverLeafCircuitWrapper;
use city_crypto::hash::merkle::core::DeltaMerkleProofCore;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::introspection::rollup::constants::SIG_ACTION_TRANSFER_MAGIC;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
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
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use serde::Deserialize;
use serde::Serialize;

use crate::introspection::gadgets::rollup::signature::compute_sig_action_hash_circuit;
use crate::state::user::l2_transfer_state_update::L2TransferStateUpdateGadget;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRL2TransferCircuitInput<F: RichField> {
    pub sender_user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub receiver_user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
    pub signature_proof_id: QProvingJobDataID,
}
impl<F: RichField> AggStateTrackableInput<F> for CRL2TransferCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: self.sender_user_tree_delta_merkle_proof.old_root,
            state_transition_end: self.receiver_user_tree_delta_merkle_proof.new_root,
        }
    }
}

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

    pub allowed_circuit_hashes_root_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub network_magic: u64,

    // dependencies
    pub signature_circuit_common_data: CommonCircuitData<C::F, D>,
    pub signature_circuit_verifier_data: VerifierOnlyCircuitData<C, D>,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone for CRL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new_with_sig_wrapper_data(
            self.network_magic,
            self.signature_circuit_common_data.clone(),
            self.signature_circuit_verifier_data.clone(),
        )
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(network_magic: u64) -> Self {
        let sig_wrapper = ZKSignatureWrapperCircuit::<C, D>::new().circuit_data;

        Self::new_with_sig_wrapper_data(
            network_magic,
            sig_wrapper.common,
            sig_wrapper.verifier_only,
        )
    }
    pub fn new_with_sig_wrapper_data(
        network_magic: u64,
        signature_circuit_common_data: CommonCircuitData<C::F, D>,
        signature_circuit_verifier_data: VerifierOnlyCircuitData<C, D>,
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
            builder.constant_verifier_data(&signature_circuit_verifier_data);

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

        let allowed_circuit_hashes_root_target = builder.add_virtual_hash();

        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            l2_transfer_single_gadget.old_user_tree_root,
            l2_transfer_single_gadget.new_user_tree_root,
        );

        builder.register_public_inputs(&allowed_circuit_hashes_root_target.elements);
        builder.register_public_inputs(&state_transition_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            l2_transfer_single_gadget,
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
        input: &CRL2TransferCircuitInput<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        self.l2_transfer_single_gadget
            .l2_transfer_gadget
            .set_witness(
                &mut pw,
                &input.sender_user_tree_delta_merkle_proof,
                &input.receiver_user_tree_delta_merkle_proof,
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

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRL2TransferCircuitInput<C::F>, C, D>
    for CRL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &CRL2TransferCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let signature_proof = store.get_proof_by_id(input.signature_proof_id)?;
        self.prove_base(input, &signature_proof)
    }
}

pub type WCRL2TransferCircuit<C, const D: usize> =
    TreeProverLeafCircuitWrapper<CRL2TransferCircuit<C, D>, C, D>;
