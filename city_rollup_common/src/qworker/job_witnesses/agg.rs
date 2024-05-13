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
