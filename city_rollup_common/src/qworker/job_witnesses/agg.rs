use city_crypto::hash::merkle::treeprover::{AggStateTransition, AggStateTransitionWithEvents};
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::qworker::job_id::QProvingJobDataID;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAggUserRegisterClaimDepositL2TransferCircuitInput<F: RichField> {
    pub op_register_user_transition_user_state_tree: AggStateTransition<F>,
    pub op_register_user_proof_id: QProvingJobDataID,

    pub op_claim_l1_deposit_transition_deposit_tree: AggStateTransition<F>,
    pub op_claim_l1_deposit_transition_user_state_tree: AggStateTransition<F>,
    pub op_claim_l1_deposit_proof_id: QProvingJobDataID,

    pub op_l2_transfer_transition_user_state_tree: AggStateTransition<F>,
    pub op_l2_transfer_proof_id: QProvingJobDataID,
}
impl<F: RichField> CRAggUserRegisterClaimDepositL2TransferCircuitInput<F> {
    pub fn get_agg_state_transition(
        &self,
        proof_id: QProvingJobDataID,
    ) -> CRAggUserRegisterClaimDepositL2TransferStateTransition<F> {
        CRAggUserRegisterClaimDepositL2TransferStateTransition {
            user_state_tree_transition: AggStateTransition::new(
                self.op_register_user_transition_user_state_tree
                    .state_transition_start,
                self.op_l2_transfer_transition_user_state_tree
                    .state_transition_end,
            ),
            deposit_tree_transition: self.op_claim_l1_deposit_transition_deposit_tree,
            proof_id,
        }
    }
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAggUserRegisterClaimDepositL2TransferStateTransition<F: RichField> {
    pub user_state_tree_transition: AggStateTransition<F>,
    pub deposit_tree_transition: AggStateTransition<F>,
    pub proof_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<F: RichField> {
    pub op_add_l1_withdrawal_transition_user_state_tree: AggStateTransition<F>,
    pub op_add_l1_withdrawal_transition_withdrawal_tree: AggStateTransition<F>,
    pub op_add_l1_withdrawal_proof_id: QProvingJobDataID,

    pub op_process_l1_withdrawal_transition_withdrawal_tree: AggStateTransition<F>,
    pub op_process_l1_withdrawal_proof_id: QProvingJobDataID,

    pub op_add_l1_deposit_transition_deposit_tree: AggStateTransition<F>,
    pub op_add_l1_deposit_proof_id: QProvingJobDataID,
}

impl<F: RichField> CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<F> {
    pub fn get_agg_state_transition(
        &self,
        proof_id: QProvingJobDataID,
    ) -> CRAggAddProcessL1WithdrawalAddL1DepositStateTransition<F> {
        CRAggAddProcessL1WithdrawalAddL1DepositStateTransition {
            user_state_tree_transition: self.op_add_l1_withdrawal_transition_user_state_tree,
            deposit_tree_transition: self.op_add_l1_deposit_transition_deposit_tree,
            withdrawal_tree_transition: AggStateTransition::new(
                self.op_add_l1_withdrawal_transition_withdrawal_tree
                    .state_transition_start,
                self.op_process_l1_withdrawal_transition_withdrawal_tree
                    .state_transition_end,
            ),
            proof_id,
        }
    }
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAggAddProcessL1WithdrawalAddL1DepositStateTransition<F: RichField> {
    pub user_state_tree_transition: AggStateTransition<F>,
    pub withdrawal_tree_transition: AggStateTransition<F>,
    pub deposit_tree_transition: AggStateTransition<F>,
    pub proof_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRBlockStateTransitionCircuitInput<F: RichField> {
    pub agg_user_register_claim_deposits_l2_transfer:
        CRAggUserRegisterClaimDepositL2TransferStateTransition<F>,
    pub agg_add_process_withdrawals_add_l1_deposit:
        CRAggAddProcessL1WithdrawalAddL1DepositStateTransition<F>,
}

impl<F: RichField> CRBlockStateTransitionCircuitInput<F> {
    pub fn from_steps(
        step_1_proof_id: QProvingJobDataID,
        step_1_input: &CRAggUserRegisterClaimDepositL2TransferCircuitInput<F>,
        step_2_proof_id: QProvingJobDataID,
        step_2_input: &CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<F>,
    ) -> Self {
        Self {
            agg_user_register_claim_deposits_l2_transfer: step_1_input
                .get_agg_state_transition(step_1_proof_id),
            agg_add_process_withdrawals_add_l1_deposit: step_2_input
                .get_agg_state_transition(step_2_proof_id),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAggL2TransferAddL1WithdrawalCircuitInput<F: RichField> {
    pub op_l2_transfer_transition_user_state_tree: AggStateTransition<F>,
    pub op_l2_transfer_proof_id: QProvingJobDataID,

    pub op_add_l1_withdrawal_transition_withdrawal_tree: AggStateTransition<F>,
    pub op_add_l1_withdrawal_transition_user_state_tree: AggStateTransition<F>,
    pub op_add_l1_withdrawal_proof_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRAggProcessL1WithdrawalAddL1DepositCircuitInput<F: RichField> {
    pub op_process_l1_withdrawal_transition_withdrawal_tree: AggStateTransitionWithEvents<F>,
    pub op_process_l1_withdrawal_proof_id: QProvingJobDataID,

    pub op_add_l1_deposit_transition_deposit_tree: AggStateTransitionWithEvents<F>,
    pub op_add_l1_deposit_proof_id: QProvingJobDataID,
}
