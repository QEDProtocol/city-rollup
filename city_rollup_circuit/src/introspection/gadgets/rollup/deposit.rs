use city_common::config::rollup_constants::NONCE_BIT_SIZE;
use city_common_circuit::builder::comparison::CircuitBuilderComparison;
use city_common_circuit::builder::core::CircuitBuilderHelpersCore;
use city_common_circuit::builder::hash::core::CircuitBuilderHashCore;
use city_common_circuit::crypto::secp256k1::gadget::DogeQEDSignatureCombinedHashGadget;
use city_common_circuit::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;
use city_crypto::hash::merkle::core::DeltaMerkleProof;
use city_crypto::hash::traits::hasher::MerkleZeroHasher;
use city_rollup_common::introspection::rollup::constants::SIG_ACTION_CLAIM_DEPOSIT_MAGIC;
use city_rollup_common::introspection::rollup::introspection_result::BTCRollupIntrospectionResultDeposit;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use super::introspection_result::BTCRollupIntrospectionResultDepositGadget;
use super::signature::compute_sig_action_hash_circuit;

#[derive(Clone, Debug)]
pub struct AddDepositGadget {
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProofGadget,
}

impl AddDepositGadget {
    pub fn add_virtual_to<
        H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        deposit_tree_height: usize,
    ) -> Self {
        let deposit_tree_delta_merkle_proof = DeltaMerkleProofGadget::add_virtual_to_append_only::<
            H,
            F,
            D,
        >(builder, deposit_tree_height);
        Self {
            deposit_tree_delta_merkle_proof,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClaimDepositGadget {
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProofGadget,
    pub user_tree_delta_merkle_proof: DeltaMerkleProofGadget,
    pub deposit_gadget: BTCRollupIntrospectionResultDepositGadget,
    pub user: Target,

    // computed:
    pub deposit_hash: HashOutTarget,
    pub sig_hash: HashOutTarget,
    pub combined_transition_hash: HashOutTarget,
}

impl ClaimDepositGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        deposit_tree_height: usize,
        user_tree_height: usize,
        network_magic: u64,
    ) -> Self {
        let deposit_tree_delta_merkle_proof =
            DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, deposit_tree_height);

        let user_tree_delta_merkle_proof =
            DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, user_tree_height);

        let deposit_gadget = BTCRollupIntrospectionResultDepositGadget::add_virtual_to(builder);
        let user = builder.add_virtual_target();

        // end inputs
        let new_nonce = user_tree_delta_merkle_proof.new_value.elements[1];
        let old_nonce = user_tree_delta_merkle_proof.old_value.elements[1];
        let deposit_hash = deposit_gadget.get_hash::<H, F, D>(builder);
        let sig_action_id = builder.constant_u64(SIG_ACTION_CLAIM_DEPOSIT_MAGIC);
        let network_magic_target = builder.constant_u64(network_magic);

        let sig_action_hash = compute_sig_action_hash_circuit::<H, F, D>(
            builder,
            network_magic_target,
            user,
            sig_action_id,
            new_nonce,
            &[
                deposit_gadget.txid_224.elements[0],
                deposit_gadget.txid_224.elements[1],
                deposit_gadget.txid_224.elements[2],
                deposit_gadget.txid_224.elements[3],
                deposit_gadget.value,
            ],
        );

        let combo_gadget = DogeQEDSignatureCombinedHashGadget::add_virtual_to_known::<H, F, D>(
            builder,
            deposit_gadget.public_key,
            sig_action_hash,
        );

        let transition_hash_old = builder.hash_two_to_one::<H>(
            user_tree_delta_merkle_proof.old_root,
            deposit_tree_delta_merkle_proof.old_root,
        );
        let transition_hash_new = builder.hash_two_to_one::<H>(
            user_tree_delta_merkle_proof.new_root,
            deposit_tree_delta_merkle_proof.new_root,
        );

        let combined_transition_hash =
            builder.hash_two_to_one::<H>(transition_hash_old, transition_hash_new);

        // start constrain

        let computed_user_leaf_index = builder.mul_const(F::from_canonical_u8(2), user);
        builder.connect(user_tree_delta_merkle_proof.index, computed_user_leaf_index);

        let computed_new_user_balance = builder.add(
            user_tree_delta_merkle_proof.old_value.elements[0],
            deposit_gadget.value,
        );

        builder.connect(
            user_tree_delta_merkle_proof.new_value.elements[0],
            computed_new_user_balance,
        );
        builder.ensure_is_greater_than(NONCE_BIT_SIZE, new_nonce, old_nonce);
        builder.connect(
            user_tree_delta_merkle_proof.old_value.elements[2],
            user_tree_delta_merkle_proof.new_value.elements[2],
        );
        builder.connect(
            user_tree_delta_merkle_proof.old_value.elements[3],
            user_tree_delta_merkle_proof.new_value.elements[3],
        );

        builder.connect_hashes(deposit_tree_delta_merkle_proof.old_value, deposit_hash);
        let updated_deposit_hash = builder.constant_hash(HashOut {
            elements: [F::ONE; 4],
        });
        builder.connect_hashes(
            deposit_tree_delta_merkle_proof.new_value,
            updated_deposit_hash,
        );

        // end constrain

        Self {
            deposit_tree_delta_merkle_proof,
            user_tree_delta_merkle_proof,
            deposit_gadget,
            user,
            deposit_hash,
            sig_hash: combo_gadget.combined_hash,
            combined_transition_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        deposit_tree_delta_merkle_proof: &DeltaMerkleProof<F>,
        user_tree_delta_merkle_proof: &DeltaMerkleProof<F>,
        deposit_result: &BTCRollupIntrospectionResultDeposit<F>,
    ) {
        self.deposit_tree_delta_merkle_proof
            .set_witness_proof(witness, deposit_tree_delta_merkle_proof);
        self.user_tree_delta_merkle_proof
            .set_witness_proof(witness, user_tree_delta_merkle_proof);
        self.deposit_gadget.set_witness(witness, deposit_result);
        witness.set_target(
            self.user,
            F::from_canonical_u64(user_tree_delta_merkle_proof.index.to_canonical_u64() / 2u64),
        );
    }
}
