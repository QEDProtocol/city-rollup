use city_common_circuit::treeprover::aggregation::gadgets::AggStateTransitionGadget;
use city_rollup_common::qworker::job_witnesses::agg::CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

#[derive(Debug, Clone)]
pub struct AggAddProcessL1WithdrawalAddL1DepositGadget {
    pub op_add_l1_withdrawal_transition_user_state_tree: AggStateTransitionGadget,
    pub op_add_l1_withdrawal_transition_withdrawal_tree: AggStateTransitionGadget,

    pub op_process_l1_withdrawal_transition_withdrawal_tree: AggStateTransitionGadget,

    pub op_add_l1_deposit_transition_deposit_tree: AggStateTransitionGadget,

    pub combined_state_transition: AggStateTransitionGadget,
    pub combined_state_transition_hash: HashOutTarget,
}

impl AggAddProcessL1WithdrawalAddL1DepositGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let op_add_l1_withdrawal_transition_user_state_tree =
            AggStateTransitionGadget::add_virtual_to(builder);
        let op_add_l1_withdrawal_transition_withdrawal_tree =
            AggStateTransitionGadget::add_virtual_to(builder);

        let op_process_l1_withdrawal_transition_withdrawal_tree =
            AggStateTransitionGadget::add_virtual_to(builder);

        let op_add_l1_deposit_transition_deposit_tree =
            AggStateTransitionGadget::add_virtual_to(builder);

        builder.connect_hashes(
            op_add_l1_withdrawal_transition_withdrawal_tree.state_transition_end,
            op_process_l1_withdrawal_transition_withdrawal_tree.state_transition_start,
        );

        let user_state_tree_transition = op_add_l1_withdrawal_transition_user_state_tree;
        let withdrawal_tree_transition = AggStateTransitionGadget {
            state_transition_start: op_add_l1_withdrawal_transition_withdrawal_tree
                .state_transition_start,
            state_transition_end: op_process_l1_withdrawal_transition_withdrawal_tree
                .state_transition_end,
        };

        let deposit_state_tree_transition = op_add_l1_deposit_transition_deposit_tree;
        let combined_state_transition = AggStateTransitionGadget::combine_many::<H, F, D>(
            builder,
            &[
                user_state_tree_transition,
                withdrawal_tree_transition,
                deposit_state_tree_transition,
            ],
        );

        let combined_state_transition_hash =
            combined_state_transition.get_combined_hash::<H, F, D>(builder);

        Self {
            op_add_l1_withdrawal_transition_user_state_tree,
            op_add_l1_withdrawal_transition_withdrawal_tree,
            op_process_l1_withdrawal_transition_withdrawal_tree,
            op_add_l1_deposit_transition_deposit_tree,
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
        actual_op_add_l1_withdrawal_combined_state_transition: HashOutTarget,
        actual_op_process_l1_withdrawal_combined_state_transition: HashOutTarget,
        actual_op_add_l1_deposit_combined_state_transition: HashOutTarget,
    ) {
        let expected_op_add_l1_withdrawal_combined_state_transition =
            AggStateTransitionGadget::combine_many::<H, F, D>(
                builder,
                &[
                    self.op_add_l1_withdrawal_transition_user_state_tree,
                    self.op_add_l1_withdrawal_transition_withdrawal_tree,
                ],
            )
            .get_combined_hash::<H, F, D>(builder);

        let expected_op_process_l1_withdrawal_combined_state_transition = self
            .op_process_l1_withdrawal_transition_withdrawal_tree
            .get_combined_hash::<H, F, D>(builder);

        let expected_op_add_l1_deposit_combined_state_transition = self
            .op_add_l1_deposit_transition_deposit_tree
            .get_combined_hash::<H, F, D>(builder);

        builder.connect_hashes(
            actual_op_add_l1_withdrawal_combined_state_transition,
            expected_op_add_l1_withdrawal_combined_state_transition,
        );

        builder.connect_hashes(
            actual_op_process_l1_withdrawal_combined_state_transition,
            expected_op_process_l1_withdrawal_combined_state_transition,
        );

        builder.connect_hashes(
            actual_op_add_l1_deposit_combined_state_transition,
            expected_op_add_l1_deposit_combined_state_transition,
        );
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<F>,
    ) {
        self.op_add_l1_withdrawal_transition_user_state_tree
            .set_witness(
                witness,
                &input.op_add_l1_withdrawal_transition_user_state_tree,
            );
        self.op_add_l1_withdrawal_transition_withdrawal_tree
            .set_witness(
                witness,
                &input.op_add_l1_withdrawal_transition_withdrawal_tree,
            );

        self.op_process_l1_withdrawal_transition_withdrawal_tree
            .set_witness(
                witness,
                &input.op_process_l1_withdrawal_transition_withdrawal_tree,
            );

        self.op_add_l1_deposit_transition_deposit_tree
            .set_witness(witness, &input.op_add_l1_deposit_transition_deposit_tree);
    }
}
