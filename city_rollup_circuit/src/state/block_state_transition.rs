use city_common_circuit::treeprover::aggregation::gadgets::AggStateTransitionGadget;
use city_rollup_common::qworker::job_witnesses::agg::{
    CRAggAddProcessL1WithdrawalAddL1DepositStateTransition,
    CRAggUserRegisterClaimDepositL2TransferStateTransition, CRBlockStateTransitionCircuitInput,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

#[derive(Debug, Clone)]
pub struct AggUserRegisterClaimDepositL2TransferStateTransitionGadget {
    pub user_state_tree_transition: AggStateTransitionGadget,
    pub deposit_tree_transition: AggStateTransitionGadget,
    pub combined_state_transition: AggStateTransitionGadget,
    pub combined_state_transition_hash: HashOutTarget,
}

impl AggUserRegisterClaimDepositL2TransferStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let user_state_tree_transition = AggStateTransitionGadget::add_virtual_to(builder);

        let deposit_tree_transition = AggStateTransitionGadget::add_virtual_to(builder);

        let combined_state_transition = AggStateTransitionGadget::combine_many::<H, F, D>(
            builder,
            &[user_state_tree_transition, deposit_tree_transition],
        );

        let combined_state_transition_hash =
            combined_state_transition.get_combined_hash::<H, F, D>(builder);

        Self {
            user_state_tree_transition,
            deposit_tree_transition,
            combined_state_transition,
            combined_state_transition_hash,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &CRAggUserRegisterClaimDepositL2TransferStateTransition<F>,
    ) {
        self.user_state_tree_transition
            .set_witness(witness, &input.user_state_tree_transition);

        self.deposit_tree_transition
            .set_witness(witness, &input.deposit_tree_transition);
    }
}
#[derive(Debug, Clone)]
pub struct AggAddProcessL1WithdrawalAddL1DepositStateTransitionGadget {
    pub user_state_tree_transition: AggStateTransitionGadget,
    pub withdrawal_tree_transition: AggStateTransitionGadget,
    pub deposit_tree_transition: AggStateTransitionGadget,
    pub combined_state_transition: AggStateTransitionGadget,
    pub combined_state_transition_hash: HashOutTarget,
}

impl AggAddProcessL1WithdrawalAddL1DepositStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let user_state_tree_transition = AggStateTransitionGadget::add_virtual_to(builder);

        let withdrawal_tree_transition = AggStateTransitionGadget::add_virtual_to(builder);

        let deposit_tree_transition = AggStateTransitionGadget::add_virtual_to(builder);

        let combined_state_transition = AggStateTransitionGadget::combine_many::<H, F, D>(
            builder,
            &[
                user_state_tree_transition,
                withdrawal_tree_transition,
                deposit_tree_transition,
            ],
        );

        let combined_state_transition_hash =
            combined_state_transition.get_combined_hash::<H, F, D>(builder);

        Self {
            user_state_tree_transition,
            withdrawal_tree_transition,
            deposit_tree_transition,
            combined_state_transition,
            combined_state_transition_hash,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &CRAggAddProcessL1WithdrawalAddL1DepositStateTransition<F>,
    ) {
        self.user_state_tree_transition
            .set_witness(witness, &input.user_state_tree_transition);

        self.withdrawal_tree_transition
            .set_witness(witness, &input.withdrawal_tree_transition);

        self.deposit_tree_transition
            .set_witness(witness, &input.deposit_tree_transition);
    }
}

#[derive(Debug, Clone)]
pub struct BlockStateTransitionGadget {
    pub agg_user_register_claim_deposits_l2_transfer:
        AggUserRegisterClaimDepositL2TransferStateTransitionGadget,
    pub agg_add_process_withdrawals_add_l1_deposit:
        AggAddProcessL1WithdrawalAddL1DepositStateTransitionGadget,

    pub deposit_events_hash: HashOutTarget,
    pub withdrawal_events_hash: HashOutTarget,

    pub combined_state_transition: AggStateTransitionGadget,
    pub combined_state_transition_hash: HashOutTarget,
}

impl BlockStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        agg_user_register_claim_deposits_l2_transfer_public_inputs: &[Target],
        agg_add_process_withdrawals_add_l1_deposit_public_inputs: &[Target],
    ) -> Self {
        assert_eq!(
            agg_user_register_claim_deposits_l2_transfer_public_inputs.len(),
            4
        );
        assert_eq!(
            agg_add_process_withdrawals_add_l1_deposit_public_inputs.len(),
            12
        );

        let actual_agg_user_register_claim_deposits_l2_transfer_state_transition_hash =
            HashOutTarget {
                elements: [
                    agg_user_register_claim_deposits_l2_transfer_public_inputs[0],
                    agg_user_register_claim_deposits_l2_transfer_public_inputs[1],
                    agg_user_register_claim_deposits_l2_transfer_public_inputs[2],
                    agg_user_register_claim_deposits_l2_transfer_public_inputs[3],
                ],
            };
        let actual_agg_add_process_withdrawals_add_l1_deposit_state_transition_hash =
            HashOutTarget {
                elements: [
                    agg_add_process_withdrawals_add_l1_deposit_public_inputs[0],
                    agg_add_process_withdrawals_add_l1_deposit_public_inputs[1],
                    agg_add_process_withdrawals_add_l1_deposit_public_inputs[2],
                    agg_add_process_withdrawals_add_l1_deposit_public_inputs[3],
                ],
            };
        let withdrawal_events_hash = HashOutTarget {
            elements: [
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[4],
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[5],
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[6],
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[7],
            ],
        };
        let deposit_events_hash = HashOutTarget {
            elements: [
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[8],
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[9],
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[10],
                agg_add_process_withdrawals_add_l1_deposit_public_inputs[11],
            ],
        };
        let agg_user_register_claim_deposits_l2_transfer =
            AggUserRegisterClaimDepositL2TransferStateTransitionGadget::add_virtual_to::<H, F, D>(
                builder,
            );

        let agg_add_process_withdrawals_add_l1_deposit =
            AggAddProcessL1WithdrawalAddL1DepositStateTransitionGadget::add_virtual_to::<H, F, D>(
                builder,
            );

        builder.connect_hashes(
            agg_user_register_claim_deposits_l2_transfer.combined_state_transition_hash,
            actual_agg_user_register_claim_deposits_l2_transfer_state_transition_hash,
        );
        builder.connect_hashes(
            agg_add_process_withdrawals_add_l1_deposit.combined_state_transition_hash,
            actual_agg_add_process_withdrawals_add_l1_deposit_state_transition_hash,
        );

        let user_state_tree_transition = AggStateTransitionGadget {
            state_transition_start: agg_user_register_claim_deposits_l2_transfer
                .user_state_tree_transition
                .state_transition_start,
            state_transition_end: agg_add_process_withdrawals_add_l1_deposit
                .user_state_tree_transition
                .state_transition_end,
        };
        let withdrawal_tree_transition =
            agg_add_process_withdrawals_add_l1_deposit.withdrawal_tree_transition;
        let deposit_tree_transition = AggStateTransitionGadget {
            state_transition_start: agg_user_register_claim_deposits_l2_transfer
                .deposit_tree_transition
                .state_transition_start,
            state_transition_end: agg_add_process_withdrawals_add_l1_deposit
                .deposit_tree_transition
                .state_transition_end,
        };
        let combined_state_transition = AggStateTransitionGadget::combine_many::<H, F, D>(
            builder,
            &[
                user_state_tree_transition,
                withdrawal_tree_transition,
                deposit_tree_transition,
            ],
        );

        let combined_state_transition_hash =
            combined_state_transition.get_combined_hash::<H, F, D>(builder);

        Self {
            agg_user_register_claim_deposits_l2_transfer,
            agg_add_process_withdrawals_add_l1_deposit,
            deposit_events_hash,
            withdrawal_events_hash,

            combined_state_transition,
            combined_state_transition_hash,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &CRBlockStateTransitionCircuitInput<F>,
    ) {
        self.agg_user_register_claim_deposits_l2_transfer
            .set_witness(witness, &input.agg_user_register_claim_deposits_l2_transfer);
        self.agg_add_process_withdrawals_add_l1_deposit
            .set_witness(witness, &input.agg_add_process_withdrawals_add_l1_deposit);
    }
}
