use city_common::config::rollup_constants::{
    GLOBAL_USER_TREE_HEIGHT, L1_WITHDRAWAL_TREE_HEIGHT, WITHDRAWAL_FEE_AMOUNT,
};
use city_common_circuit::{
    builder::{
        comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore,
        hash::core::CircuitBuilderHashCore,
    },
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
};
use city_crypto::hash::{
    merkle::core::DeltaMerkleProofCore, qhashout::QHashOut, traits::hasher::MerkleZeroHasher,
};
use city_rollup_common::introspection::rollup::constants::SIG_ACTION_WITHDRAW_MAGIC;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::introspection::gadgets::rollup::{
    introspection_result::BTCRollupIntrospectionResultWithdrawalGadget,
    signature::compute_sig_action_hash_circuit,
};

use super::user_state::UserStateGadget;

#[derive(Debug, Clone)]
pub struct AddL1WithdrawalGadget {
    // inputs:
    pub withdrawal_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget,

    // computed:
    pub old_user_state: UserStateGadget,
    pub new_user_state: UserStateGadget,
    pub withdrawal_hash: HashOutTarget,
    pub withdrawal_amount: Target,
    pub withdrawal_fee: Target,
    pub actual_user_paid_amount: Target,
}

impl AddL1WithdrawalGadget {
    pub fn add_virtual_to<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let withdrawal_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_append_only::<H, F, D>(
                builder,
                L1_WITHDRAWAL_TREE_HEIGHT as usize,
            );

        // ensure that the old value of the leaf is empty (make sure it does not overwrite an existing withdrawal)
        builder.ensure_hash_is_zero(withdrawal_tree_delta_merkle_proof_gadget.old_value);

        let withdrawal_hash = withdrawal_tree_delta_merkle_proof_gadget.new_value;

        // validate the withdrawal hash to make sure it can be processed and get the amount
        let withdrawal_amount =
            BTCRollupIntrospectionResultWithdrawalGadget::validate_withdrawal_hash_get_amount(
                builder,
                withdrawal_hash,
            );

        let user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_u8h::<H, F, D>(builder, GLOBAL_USER_TREE_HEIGHT);

        let old_user_state = UserStateGadget::new_from_delta_merkle_proof_left_leaf(
            builder,
            &user_tree_delta_merkle_proof_gadget,
        );

        // ensure the withdrawal amount is not zero
        // TODO: make sure the amount is greater than some reasonable value
        let zero = builder.zero();
        builder.ensure_not_equal(withdrawal_amount, zero);

        let withdrawal_fee = builder.constant_u64(WITHDRAWAL_FEE_AMOUNT);
        let expected_user_paid_amount = builder.add(withdrawal_amount, withdrawal_fee);

        let (actual_user_paid_amount, new_user_state) = old_user_state
            .ensure_valid_decrease_balance(
                builder,
                user_tree_delta_merkle_proof_gadget.new_value,
                true,
            );

        // ensure the amount paid by the user is equal to withdrawal_amount + WITHDRAWAL_FEE_AMOUNT
        builder.connect(expected_user_paid_amount, actual_user_paid_amount);

        Self {
            withdrawal_tree_delta_merkle_proof_gadget,
            user_tree_delta_merkle_proof_gadget,
            old_user_state,
            new_user_state,
            withdrawal_hash,
            withdrawal_amount,
            withdrawal_fee,
            actual_user_paid_amount,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        withdrawal_tree_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        user_tree_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) {
        self.withdrawal_tree_delta_merkle_proof_gadget
            .set_witness_core_proof_q(witness, withdrawal_tree_delta_merkle_proof);
        self.user_tree_delta_merkle_proof_gadget
            .set_witness_core_proof_q(witness, user_tree_delta_merkle_proof);
    }
}

#[derive(Debug, Clone)]
pub struct AddL1WithdrawalSingleGadget {
    // inputs:
    pub withdrawal_gadget: AddL1WithdrawalGadget,

    // computed:
    pub expected_signature_hash: HashOutTarget,
    pub expected_public_key: HashOutTarget,

    pub old_user_tree_root: HashOutTarget,
    pub new_user_tree_root: HashOutTarget,

    pub old_withdrawal_tree_root: HashOutTarget,
    pub new_withdrawal_tree_root: HashOutTarget,

    pub combined_state_transition_hash: HashOutTarget,
    pub add_withdrawal_event_hash: HashOutTarget,
}
impl AddL1WithdrawalSingleGadget {
    pub fn add_virtual_to<
        H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        network_magic: u64,
    ) -> Self {
        let withdrawal_gadget = AddL1WithdrawalGadget::add_virtual_to::<H, F, D>(builder);

        let sig_action_id = builder.constant_u64(SIG_ACTION_WITHDRAW_MAGIC);
        let network_magic_target = builder.constant_u64(network_magic);
        let user_id = withdrawal_gadget.old_user_state.user_id;
        let new_user_nonce = withdrawal_gadget.new_user_state.nonce;
        let withdrawal_hash = withdrawal_gadget.withdrawal_hash;
        let withdrawal_fee = withdrawal_gadget.withdrawal_fee;
/*
        let expected_signature_hash = compute_sig_action_hash_circuit::<H, F, D>(
            builder,
            network_magic_target,
            sender_user_id,
            sig_action_id,
            new_sender_user_nonce,
            &[recipient_user_id, amount],
        );
        let expected_p*/
        let expected_signature_hash = compute_sig_action_hash_circuit::<H, F, D>(
            builder,
            network_magic_target,
            user_id,
            sig_action_id,
            new_user_nonce,
            &[
                withdrawal_hash.elements[0],
                withdrawal_hash.elements[1],
                withdrawal_hash.elements[2],
                withdrawal_hash.elements[3],
                withdrawal_fee,
            ],
        );
        let expected_public_key = withdrawal_gadget.old_user_state.public_key;

        let old_user_tree_root = withdrawal_gadget
            .user_tree_delta_merkle_proof_gadget
            .old_root;
        let new_user_tree_root = withdrawal_gadget
            .user_tree_delta_merkle_proof_gadget
            .new_root;

        let old_withdrawal_tree_root = withdrawal_gadget
            .withdrawal_tree_delta_merkle_proof_gadget
            .old_root;
        let new_withdrawal_tree_root = withdrawal_gadget
            .withdrawal_tree_delta_merkle_proof_gadget
            .new_root;

        let old_state_transition_hash =
            builder.hash_two_to_one::<H>(old_user_tree_root, old_withdrawal_tree_root);

        let new_state_transition_hash =
            builder.hash_two_to_one::<H>(new_user_tree_root, new_withdrawal_tree_root);

        let combined_state_transition_hash =
            builder.hash_two_to_one::<H>(old_state_transition_hash, new_state_transition_hash);

        let add_withdrawal_event_hash = withdrawal_hash;

        Self {
            withdrawal_gadget,
            expected_signature_hash,
            expected_public_key,
            old_user_tree_root,
            new_user_tree_root,
            old_withdrawal_tree_root,
            new_withdrawal_tree_root,
            combined_state_transition_hash,
            add_withdrawal_event_hash,
        }
    }
}
