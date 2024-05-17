use city_common::config::rollup_constants::{
    BALANCE_BIT_SIZE, DEPOSIT_FEE_AMOUNT, GLOBAL_USER_TREE_HEIGHT, L1_DEPOSIT_TREE_HEIGHT,
};
use city_common_circuit::{
    builder::{
        comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore,
        hash::core::CircuitBuilderHashCore,
    },
    crypto::secp256k1::gadget::DogeQEDSignatureCombinedHashGadget,
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
};
use city_crypto::hash::{merkle::core::DeltaMerkleProofCore, qhashout::QHashOut};
use city_rollup_common::introspection::rollup::{
    constants::SIG_ACTION_CLAIM_DEPOSIT_MAGIC,
    introspection_result::BTCRollupIntrospectionResultDeposit,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::introspection::gadgets::rollup::{
    introspection_result::BTCRollupIntrospectionResultDepositGadget,
    signature::compute_sig_action_hash_circuit,
};

use super::user_state::UserStateGadget;

#[derive(Debug, Clone)]
pub struct ClaimL1DepositGadget {
    // inputs:
    pub deposit_gadget: BTCRollupIntrospectionResultDepositGadget,
    pub deposit_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget,
    pub user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget,

    // computed:
    pub old_user_state: UserStateGadget,
    pub new_user_state: UserStateGadget,
    pub deposit_hash: HashOutTarget,
    pub claim_amount: Target,
    pub deposit_amount: Target,
}

impl ClaimL1DepositGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let deposit_gadget = BTCRollupIntrospectionResultDepositGadget::add_virtual_to(builder);

        let deposit_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_u8h::<H, F, D>(builder, L1_DEPOSIT_TREE_HEIGHT);

        let deposit_hash = deposit_gadget.get_hash::<H, F, D>(builder);

        // ensure that the deposit hash is the old value from our delta merkle proof
        builder.connect_hashes(
            deposit_hash,
            deposit_tree_delta_merkle_proof_gadget.old_value,
        );

        // ensure that the new value of the leaf is empty (mark deposit as claimed)
        builder.ensure_hash_is_zero(deposit_tree_delta_merkle_proof_gadget.new_value);

        let user_tree_delta_merkle_proof_gadget: DeltaMerkleProofGadget =
            DeltaMerkleProofGadget::add_virtual_to_u8h::<H, F, D>(builder, GLOBAL_USER_TREE_HEIGHT);

        let old_user_state = UserStateGadget::new_from_delta_merkle_proof_left_leaf(
            builder,
            &user_tree_delta_merkle_proof_gadget,
        );
        let deposit_amount = deposit_gadget.value;
        let deposit_fee = builder.constant_u64(DEPOSIT_FEE_AMOUNT);
        builder.ensure_is_greater_than(BALANCE_BIT_SIZE, deposit_amount, deposit_fee);

        let claim_amount = builder.sub(deposit_amount, deposit_fee);

        // add deposit_gadget.value to the user's existing balance
        let new_user_state = old_user_state.ensure_valid_increase_balance_known_amount(
            builder,
            user_tree_delta_merkle_proof_gadget.new_value,
            claim_amount,
            false,
        );

        Self {
            deposit_gadget,
            deposit_tree_delta_merkle_proof_gadget,
            user_tree_delta_merkle_proof_gadget,

            old_user_state,
            new_user_state,
            deposit_hash,
            deposit_amount,
            claim_amount,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        deposit: &BTCRollupIntrospectionResultDeposit<F>,
        deposit_tree_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        user_tree_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) {
        self.deposit_gadget.set_witness(witness, deposit);

        self.deposit_tree_delta_merkle_proof_gadget
            .set_witness_core_proof_q(witness, deposit_tree_delta_merkle_proof);
        self.user_tree_delta_merkle_proof_gadget
            .set_witness_core_proof_q(witness, user_tree_delta_merkle_proof);
    }
}

#[derive(Debug, Clone)]
pub struct ClaimL1DepositSingleGadget {
    // inputs:
    pub claim_gadget: ClaimL1DepositGadget,

    // computed:
    pub signature_combo_gadget: DogeQEDSignatureCombinedHashGadget,
    pub expected_l1_signature_hash: HashOutTarget,
    pub old_state_transition_hash: HashOutTarget,
    pub new_state_transition_hash: HashOutTarget,
    pub combined_state_transition_hash: HashOutTarget,
    pub claim_deposit_event_hash: HashOutTarget,
}
impl ClaimL1DepositSingleGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        network_magic: u64,
    ) -> Self {
        let claim_gadget = ClaimL1DepositGadget::add_virtual_to::<H, F, D>(builder);
        let sig_action_id = builder.constant_u64(SIG_ACTION_CLAIM_DEPOSIT_MAGIC);
        let network_magic_target = builder.constant_u64(network_magic);
        let user_id = claim_gadget.old_user_state.user_id;
        let nonce = builder.zero(); //nonce is 0 for claiming deposits
        let claimed_tx_id_224 = claim_gadget.deposit_gadget.txid_224;
        let deposit_amount = claim_gadget.deposit_amount;
        let deposit_fee = builder.constant_u64(DEPOSIT_FEE_AMOUNT);
        let claim_l1_public_key = claim_gadget.deposit_gadget.public_key;

        let sig_action_hash = compute_sig_action_hash_circuit::<H, F, D>(
            builder,
            network_magic_target,
            user_id,
            sig_action_id,
            nonce,
            &[
                claimed_tx_id_224.elements[0],
                claimed_tx_id_224.elements[1],
                claimed_tx_id_224.elements[2],
                claimed_tx_id_224.elements[3],
                deposit_amount,
                deposit_fee,
            ],
        );

        let signature_combo_gadget = DogeQEDSignatureCombinedHashGadget::add_virtual_to_known::<
            H,
            F,
            D,
        >(builder, claim_l1_public_key, sig_action_hash);

        let old_state_transition_hash = builder.hash_two_to_one::<H>(
            claim_gadget.user_tree_delta_merkle_proof_gadget.old_root,
            claim_gadget.deposit_tree_delta_merkle_proof_gadget.old_root,
        );
        let new_state_transition_hash = builder.hash_two_to_one::<H>(
            claim_gadget.user_tree_delta_merkle_proof_gadget.new_root,
            claim_gadget.deposit_tree_delta_merkle_proof_gadget.new_root,
        );

        let combined_transition_hash =
            builder.hash_two_to_one::<H>(old_state_transition_hash, new_state_transition_hash);

        let claim_deposit_event_hash = claim_gadget.deposit_hash;

        Self {
            claim_gadget,
            signature_combo_gadget,
            expected_l1_signature_hash: sig_action_hash,
            old_state_transition_hash,
            new_state_transition_hash,
            combined_state_transition_hash: combined_transition_hash,
            claim_deposit_event_hash,
        }
    }
}
