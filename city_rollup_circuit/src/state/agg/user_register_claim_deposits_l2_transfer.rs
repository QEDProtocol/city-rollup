use city_common_circuit::treeprover::aggregation::gadgets::AggStateTransitionGadget;
use city_rollup_common::qworker::job_witnesses::agg::CRAggUserRegisterClaimDepositL2TransferCircuitInput;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

#[derive(Debug, Clone)]
pub struct AggUserRegisterClaimDepositL2TransferGadget {
    pub op_register_user_transition_user_state_tree: AggStateTransitionGadget,

    pub op_claim_l1_deposit_transition_deposit_tree: AggStateTransitionGadget,
    pub op_claim_l1_deposit_transition_user_state_tree: AggStateTransitionGadget,

    pub op_l2_transfer_transition_user_state_tree: AggStateTransitionGadget,

    pub combined_state_transition: AggStateTransitionGadget,
    pub combined_state_transition_hash: HashOutTarget,
}

impl AggUserRegisterClaimDepositL2TransferGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let op_register_user_transition_user_state_tree =
            AggStateTransitionGadget::add_virtual_to(builder);

        let op_claim_l1_deposit_transition_deposit_tree =
            AggStateTransitionGadget::add_virtual_to(builder);
        let op_claim_l1_deposit_transition_user_state_tree =
            AggStateTransitionGadget::add_virtual_to(builder);

        let op_l2_transfer_transition_user_state_tree =
            AggStateTransitionGadget::add_virtual_to(builder);

        builder.connect_hashes(
            op_register_user_transition_user_state_tree.state_transition_end,
            op_claim_l1_deposit_transition_user_state_tree.state_transition_start,
        );
        builder.connect_hashes(
            op_claim_l1_deposit_transition_user_state_tree.state_transition_end,
            op_l2_transfer_transition_user_state_tree.state_transition_start,
        );

        let user_state_tree_transition = AggStateTransitionGadget {
            state_transition_start: op_register_user_transition_user_state_tree
                .state_transition_start,
            state_transition_end: op_l2_transfer_transition_user_state_tree.state_transition_end,
        };

        let deposit_state_tree_transition = op_claim_l1_deposit_transition_deposit_tree;
        let combined_state_transition = AggStateTransitionGadget::combine_many::<H, F, D>(
            builder,
            &[user_state_tree_transition, deposit_state_tree_transition],
        );

        let combined_state_transition_hash =
            combined_state_transition.get_combined_hash::<H, F, D>(builder);

        Self {
            op_claim_l1_deposit_transition_deposit_tree,
            op_claim_l1_deposit_transition_user_state_tree,
            op_l2_transfer_transition_user_state_tree,
            op_register_user_transition_user_state_tree,
            combined_state_transition,
            combined_state_transition_hash,
        }
    }
    pub fn connect_to_proof_results<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        actual_op_register_user_combined_state_transition: HashOutTarget,
        actual_op_claim_l1_deposit_combined_state_transition: HashOutTarget,
        actual_op_l2_transfer_combined_state_transition: HashOutTarget,
    ) {
        let expected_op_register_user_combined_state_transition = self
            .op_register_user_transition_user_state_tree
            .get_combined_hash::<H, F, D>(builder);

        let expected_op_claim_l1_deposit_combined_state_transition =
            AggStateTransitionGadget::combine_many::<H, F, D>(
                builder,
                &[
                    self.op_claim_l1_deposit_transition_user_state_tree,
                    self.op_claim_l1_deposit_transition_deposit_tree,
                ],
            )
            .get_combined_hash::<H, F, D>(builder);

        let expected_op_l2_transfer_combined_state_transition = self
            .op_register_user_transition_user_state_tree
            .get_combined_hash::<H, F, D>(builder);

        builder.connect_hashes(
            actual_op_register_user_combined_state_transition,
            expected_op_register_user_combined_state_transition,
        );

        builder.connect_hashes(
            actual_op_claim_l1_deposit_combined_state_transition,
            expected_op_claim_l1_deposit_combined_state_transition,
        );

        builder.connect_hashes(
            actual_op_l2_transfer_combined_state_transition,
            expected_op_l2_transfer_combined_state_transition,
        );
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &CRAggUserRegisterClaimDepositL2TransferCircuitInput<F>,
    ) {
        self.op_register_user_transition_user_state_tree
            .set_witness(witness, &input.op_register_user_transition_user_state_tree);

        self.op_claim_l1_deposit_transition_deposit_tree
            .set_witness(witness, &input.op_claim_l1_deposit_transition_deposit_tree);
        self.op_claim_l1_deposit_transition_user_state_tree
            .set_witness(
                witness,
                &input.op_claim_l1_deposit_transition_user_state_tree,
            );

        self.op_l2_transfer_transition_user_state_tree
            .set_witness(witness, &input.op_l2_transfer_transition_user_state_tree);
    }
}
