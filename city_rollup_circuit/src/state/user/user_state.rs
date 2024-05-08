use city_common::config::rollup_constants::BALANCE_BIT_SIZE;
use city_common::config::rollup_constants::GLOBAL_USER_TREE_HEIGHT;
use city_common::config::rollup_constants::NONCE_BIT_SIZE;
use city_common_circuit::builder::comparison::CircuitBuilderComparison;
use city_common_circuit::builder::hash::core::CircuitBuilderHashCore;
use city_common_circuit::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
#[derive(Debug, Clone, Copy)]
pub struct UserStateGadget {
    pub user_id: Target,
    pub balance: Target,
    pub nonce: Target,
    pub alt_user_state_slot_a: Target,
    pub alt_user_state_slot_b: Target,
    pub public_key: HashOutTarget,
    pub is_left_leaf_index: bool,
}

impl UserStateGadget {
    pub fn new_from_leaves_and_id(
        user_id: Target,
        left_leaf: HashOutTarget,
        right_leaf: HashOutTarget,
        is_left_leaf_index: bool,
    ) -> Self {
        let balance = left_leaf.elements[0];
        let nonce = left_leaf.elements[1];
        let alt_user_state_slot_a = left_leaf.elements[2];
        let alt_user_state_slot_b = left_leaf.elements[3];
        let public_key = right_leaf;
        Self {
            user_id,
            balance,
            nonce,
            alt_user_state_slot_a,
            alt_user_state_slot_b,
            public_key,
            is_left_leaf_index,
        }
    }

    pub fn new_from_leaves<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        known_user_id: Option<Target>,
        user_state_tree_leaf_index: Target,
        is_left_leaf_index: bool,
        left_leaf: HashOutTarget,
        right_leaf: HashOutTarget,
    ) -> Self {
        let zero = builder.zero();
        let one = builder.one();

        let user_id = if known_user_id.is_some() {
            let user_id = known_user_id.unwrap();
            let expected_leaf_index = if is_left_leaf_index {
                // if it is a left leaf merkle proof, then index should be user_id * 2
                builder.mul_const(F::TWO, user_id)
            } else {
                // if it is a right leaf merkle proof, then index should be user_id * 2 + 1
                builder.mul_const_add(F::TWO, user_id, one)
            };
            builder.connect(user_state_tree_leaf_index, expected_leaf_index);
            user_id
        } else {
            let leaf_index_bits =
                builder.split_le(user_state_tree_leaf_index, GLOBAL_USER_TREE_HEIGHT as usize);
            let is_right_leaf = leaf_index_bits[0];
            // user_id = index >> 1
            let user_id = builder.le_sum(leaf_index_bits[1..].iter());
            if is_left_leaf_index {
                // if it is a left leaf, then the least significant bit of the index should be 0
                // (index = even number)
                builder.connect(is_right_leaf.target, zero)
            } else {
                // if it is a right leaf, then the least significant bit of the index should be
                // 1 (index = odd number)
                builder.connect(is_right_leaf.target, one)
            }
            user_id
        };

        Self::new_from_leaves_and_id(user_id, left_leaf, right_leaf, is_left_leaf_index)
    }
    pub fn new_from_left_leaf_index<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_state_tree_leaf_index: Target,
        left_leaf: HashOutTarget,
        right_leaf: HashOutTarget,
    ) -> Self {
        Self::new_from_leaves(
            builder,
            None,
            user_state_tree_leaf_index,
            true,
            left_leaf,
            right_leaf,
        )
    }
    pub fn new_from_right_leaf_index<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_state_tree_leaf_index: Target,
        left_leaf: HashOutTarget,
        right_leaf: HashOutTarget,
    ) -> Self {
        Self::new_from_leaves(
            builder,
            None,
            user_state_tree_leaf_index,
            false,
            left_leaf,
            right_leaf,
        )
    }

    pub fn new_from_left_leaf_index_known_user_id<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_id: Target,
        user_state_tree_leaf_index: Target,
        left_leaf: HashOutTarget,
        right_leaf: HashOutTarget,
    ) -> Self {
        Self::new_from_leaves(
            builder,
            Some(user_id),
            user_state_tree_leaf_index,
            true,
            left_leaf,
            right_leaf,
        )
    }
    pub fn new_from_right_leaf_index_known_user_id<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_id: Target,
        user_state_tree_leaf_index: Target,
        left_leaf: HashOutTarget,
        right_leaf: HashOutTarget,
    ) -> Self {
        Self::new_from_leaves(
            builder,
            Some(user_id),
            user_state_tree_leaf_index,
            false,
            left_leaf,
            right_leaf,
        )
    }
    pub fn ensure_valid_decrease_balance<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        new_left_leaf: HashOutTarget,
        requires_nonce_update: bool,
    ) -> (Target, Self) {
        assert!(
            self.is_left_leaf_index,
            "User state must be left leaf to perform a balance update"
        );
        let new_balance = new_left_leaf.elements[0];
        let new_nonce = new_left_leaf.elements[1];
        let new_alt_user_state_slot_a = new_left_leaf.elements[2];
        let new_alt_user_state_slot_b = new_left_leaf.elements[3];

        // the amount to decrease the balance by is the difference between the old
        // balance and the new balance
        let amount = builder.sub(self.balance, new_balance);

        // ensure that the user can afford to decrease the balance (i.e that (balance -
        // amount) does not underflow)
        builder.ensure_is_greater_than_or_equal(BALANCE_BIT_SIZE, self.balance, amount);

        // ensure that alt_user_state_slot_a did not change
        builder.connect(new_alt_user_state_slot_a, self.alt_user_state_slot_a);

        // ensure that alt_user_state_slot_b did not change
        builder.connect(new_alt_user_state_slot_b, self.alt_user_state_slot_b);

        if requires_nonce_update {
            // if the update requires a nonce update, ensure the new nonce is greater than
            // the old nonce
            builder.ensure_is_greater_than(NONCE_BIT_SIZE, new_nonce, self.nonce)
        } else {
            // if the update does not require a nonce update, ensure the new nonce is the
            // same as the old nonce
            builder.connect(new_nonce, self.nonce);
        }
        let new_user_state = Self {
            user_id: self.user_id,
            balance: new_balance,
            nonce: new_nonce,
            alt_user_state_slot_a: new_alt_user_state_slot_a,
            alt_user_state_slot_b: new_alt_user_state_slot_b,
            public_key: self.public_key,
            is_left_leaf_index: self.is_left_leaf_index,
        };

        (amount, new_user_state)
    }
    pub fn ensure_valid_increase_balance_known_amount<
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        new_left_leaf: HashOutTarget,
        increase_amount: Target,
        requires_nonce_update: bool,
    ) -> Self {
        assert!(
            self.is_left_leaf_index,
            "User state must be left leaf to perform a balance update"
        );
        let new_balance = new_left_leaf.elements[0];
        let new_nonce = new_left_leaf.elements[1];
        let new_alt_user_state_slot_a = new_left_leaf.elements[2];
        let new_alt_user_state_slot_b = new_left_leaf.elements[3];

        // the new balance should be the old balance plus the increase amount
        let expected_new_balance = builder.add(self.balance, increase_amount);

        // ensure that new_balance == balance + increase_amount
        builder.connect(new_balance, expected_new_balance);
        // ensure that (balance + increase_amount) did not overflow
        builder.ensure_is_greater_than(BALANCE_BIT_SIZE, new_balance, self.balance);

        // ensure that alt_user_state_slot_a did not change
        builder.connect(new_alt_user_state_slot_a, self.alt_user_state_slot_a);

        // ensure that alt_user_state_slot_b did not change
        builder.connect(new_alt_user_state_slot_b, self.alt_user_state_slot_b);

        if requires_nonce_update {
            // if the update requires a nonce update, ensure the new nonce is greater than
            // the old nonce
            builder.ensure_is_greater_than(NONCE_BIT_SIZE, new_nonce, self.nonce)
        } else {
            // if the update does not require a nonce update, ensure the new nonce is the
            // same as the old nonce
            builder.connect(new_nonce, self.nonce);
        }

        Self {
            user_id: self.user_id,
            balance: new_balance,
            nonce: new_nonce,
            alt_user_state_slot_a: new_alt_user_state_slot_a,
            alt_user_state_slot_b: new_alt_user_state_slot_b,
            public_key: self.public_key,
            is_left_leaf_index: self.is_left_leaf_index,
        }
    }

    pub fn ensure_valid_new_user_registration<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        new_public_key: HashOutTarget,
    ) -> Self {
        assert_eq!(
            self.is_left_leaf_index, false,
            "User state must be right leaf to register a new user"
        );
        let zero = builder.zero();

        // new users should have a balance of 0
        builder.connect(self.balance, zero);
        // new users should have a nonce of 0
        builder.connect(self.nonce, zero);

        // new users should have a alt_user_state_slot_a of 0
        builder.connect(self.alt_user_state_slot_a, zero);

        // new users should have a alt_user_state_slot_b of 0
        builder.connect(self.alt_user_state_slot_b, zero);

        // the previous public key should be 0, otherwise the user has already been
        // registered
        builder.ensure_hash_is_zero(new_public_key);
        // the new public key should be non-zero, otherwise the user registration is
        // invalid
        builder.ensure_hash_is_non_zero(new_public_key);

        Self {
            user_id: self.user_id,
            balance: self.balance,
            nonce: self.nonce,
            alt_user_state_slot_a: self.alt_user_state_slot_a,
            alt_user_state_slot_b: self.alt_user_state_slot_b,
            public_key: new_public_key,
            is_left_leaf_index: self.is_left_leaf_index,
        }
    }

    pub fn new_from_delta_merkle_proof_left_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        delta_merkle_proof_gadget: &DeltaMerkleProofGadget,
    ) -> Self {
        Self::new_from_left_leaf_index(
            builder,
            delta_merkle_proof_gadget.index,
            delta_merkle_proof_gadget.old_value,
            delta_merkle_proof_gadget.siblings[0],
        )
    }

    pub fn new_from_delta_merkle_proof_right_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        delta_merkle_proof_gadget: &DeltaMerkleProofGadget,
    ) -> Self {
        Self::new_from_right_leaf_index(
            builder,
            delta_merkle_proof_gadget.index,
            delta_merkle_proof_gadget.old_value,
            delta_merkle_proof_gadget.siblings[0],
        )
    }
}
