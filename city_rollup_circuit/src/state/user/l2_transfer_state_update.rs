use city_common::config::rollup_constants::GLOBAL_USER_TREE_HEIGHT;
use city_common_circuit::builder::comparison::CircuitBuilderComparison;
use city_common_circuit::builder::hash::core::CircuitBuilderHashCore;
use city_common_circuit::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;
use city_crypto::hash::merkle::core::DeltaMerkleProofCore;
use city_crypto::hash::qhashout::QHashOut;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use super::user_state::UserStateGadget;

#[derive(Debug, Clone)]
pub struct L2TransferStateUpdateGadget {
    // inputs:
    pub sender_user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub receiver_user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget,

    // computed:
    pub sender_old_user_state: UserStateGadget,
    pub sender_new_user_state: UserStateGadget,
    pub receiver_old_user_state: UserStateGadget,
    pub receiver_new_user_state: UserStateGadget,
    pub transfer_amount: Target,
}

impl L2TransferStateUpdateGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let sender_user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_u8h::<H, F, D>(builder, GLOBAL_USER_TREE_HEIGHT);

        let receiver_user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_u8h::<H, F, D>(builder, GLOBAL_USER_TREE_HEIGHT);

        // ensure the receiver has a non-zero public key (i.e the receiver user already
        // exists on the network)
        builder.ensure_hash_is_non_zero(receiver_user_tree_delta_merkle_proof_gadget.siblings[0]);

        // ensure the sender has a non-zero public key (i.e the receiver user already
        // exists on the network)
        builder.ensure_hash_is_non_zero(sender_user_tree_delta_merkle_proof_gadget.siblings[0]);

        // ensure this is not a self transfer
        builder.ensure_not_equal(
            sender_user_tree_delta_merkle_proof_gadget.index,
            receiver_user_tree_delta_merkle_proof_gadget.index,
        );

        // ensure that the delta merkle proofs are back-to-back state transitions
        // 1. decrement sender's balance by X and update sender's nonce
        // 2. increment receiver's balance by X
        builder.connect_hashes(
            sender_user_tree_delta_merkle_proof_gadget.new_root,
            receiver_user_tree_delta_merkle_proof_gadget.old_root,
        );

        let sender_old_user_state = UserStateGadget::new_from_delta_merkle_proof_left_leaf(
            builder,
            &sender_user_tree_delta_merkle_proof_gadget,
        );

        let (transfer_amount, sender_new_user_state) = sender_old_user_state
            .ensure_valid_decrease_balance(
                builder,
                sender_user_tree_delta_merkle_proof_gadget.new_value,
                true,
            );

        let receiver_old_user_state = UserStateGadget::new_from_delta_merkle_proof_left_leaf(
            builder,
            &receiver_user_tree_delta_merkle_proof_gadget,
        );
        let receiver_new_user_state = receiver_old_user_state
            .ensure_valid_increase_balance_known_amount(
                builder,
                receiver_user_tree_delta_merkle_proof_gadget.new_value,
                transfer_amount,
                false,
            );
        Self {
            sender_user_tree_delta_merkle_proof_gadget,
            receiver_user_tree_delta_merkle_proof_gadget,
            sender_old_user_state,
            sender_new_user_state,
            receiver_old_user_state,
            receiver_new_user_state,
            transfer_amount: transfer_amount,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        sender_user_tree_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        receiver_user_tree_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) {
        self.sender_user_tree_delta_merkle_proof_gadget
            .set_witness_core_proof_q(witness, sender_user_tree_delta_merkle_proof);
        self.receiver_user_tree_delta_merkle_proof_gadget
            .set_witness_core_proof_q(witness, receiver_user_tree_delta_merkle_proof);
    }
}
