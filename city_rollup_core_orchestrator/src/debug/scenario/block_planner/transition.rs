use city_crypto::hash::{
    merkle::treeprover::{AggStateTransition, AggStateTransitionWithEvents},
    qhashout::QHashOut,
};
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID,
    job_witnesses::agg::CRAggUserRegisterClaimDepositL2TransferCircuitInput,
};
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityRootStateTransitions<F: RichField> {
    pub start_deposit_tree_root: QHashOut<F>,
    pub start_withdrawal_tree_root: QHashOut<F>,
    pub register_users: AggStateTransition<F>,
    pub claim_deposits: AggStateTransition<F>,
    pub token_transfers: AggStateTransition<F>,
    pub add_withdrawals: AggStateTransition<F>,
    pub process_withdrawals: AggStateTransitionWithEvents<F>,
    pub add_deposits: AggStateTransitionWithEvents<F>,
}

impl<F: RichField> CityRootStateTransitions<F> {
    pub fn get_block_state_witness_part_1(
        &self,
        jobs: &CityOpRootJobIds,
    ) -> CRAggUserRegisterClaimDepositL2TransferCircuitInput<F> {
        CRAggUserRegisterClaimDepositL2TransferCircuitInput {
            op_register_user_transition_user_state_tree: self.register_users,
            op_register_user_proof_id: jobs.register_user_job_root_id,
            op_claim_l1_deposit_transition_deposit_tree: AggStateTransition::new(
                self.start_deposit_tree_root,
                self.add_deposits.state_transition_start,
            ),
            op_claim_l1_deposit_transition_user_state_tree: AggStateTransition::new(
                self.register_users.state_transition_end,
                self.token_transfers.state_transition_start,
            ),
            op_claim_l1_deposit_proof_id: jobs.claim_deposit_job_root_id,
            op_l2_transfer_transition_user_state_tree: self.token_transfers,
            op_l2_transfer_proof_id: jobs.token_transfer_job_root_id,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityOpRootJobIds {
    pub register_user_job_root_id: QProvingJobDataID,
    pub claim_deposit_job_root_id: QProvingJobDataID,
    pub token_transfer_job_root_id: QProvingJobDataID,
    pub add_withdrawal_job_root_id: QProvingJobDataID,
    pub process_withdrawal_job_root_id: QProvingJobDataID,
    pub add_deposit_job_root_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityOpJobIds {
    pub register_user_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub claim_deposit_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub token_transfer_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub add_withdrawal_job_ids: Vec<Vec<QProvingJobDataID>>,

    pub process_withdrawal_job_ids: Vec<Vec<QProvingJobDataID>>,
    pub add_deposit_job_ids: Vec<Vec<QProvingJobDataID>>,
}
fn vec_2d_size<T>(arr: &[Vec<T>]) -> usize {
    arr.iter().map(|x| x.len()).sum()
}
impl CityOpJobIds {
    pub fn get_total_job_ids(&self) -> usize {
        vec_2d_size(&self.register_user_job_ids)
            + vec_2d_size(&self.claim_deposit_job_ids)
            + vec_2d_size(&self.token_transfer_job_ids)
            + vec_2d_size(&self.add_withdrawal_job_ids)
            + vec_2d_size(&self.process_withdrawal_job_ids)
            + vec_2d_size(&self.add_deposit_job_ids)
    }
    pub fn plan_jobs(&self) -> Vec<QProvingJobDataID> {
        let mut job_ids = Vec::with_capacity(self.get_total_job_ids());
        let max_level = self
            .register_user_job_ids
            .len()
            .max(self.claim_deposit_job_ids.len())
            .max(self.token_transfer_job_ids.len())
            .max(self.add_withdrawal_job_ids.len())
            .max(self.process_withdrawal_job_ids.len())
            .max(self.add_deposit_job_ids.len());

        for i in 0..max_level {
            if i < self.register_user_job_ids.len() {
                job_ids.extend(&self.register_user_job_ids[i]);
            }
            if i < self.claim_deposit_job_ids.len() {
                job_ids.extend(&self.claim_deposit_job_ids[i]);
            }
            if i < self.token_transfer_job_ids.len() {
                job_ids.extend(&self.token_transfer_job_ids[i]);
            }
            if i < self.add_withdrawal_job_ids.len() {
                job_ids.extend(&self.add_withdrawal_job_ids[i]);
            }
            if i < self.process_withdrawal_job_ids.len() {
                job_ids.extend(&self.process_withdrawal_job_ids[i]);
            }
            if i < self.add_deposit_job_ids.len() {
                job_ids.extend(&self.add_deposit_job_ids[i]);
            }
        }

        job_ids
    }
    pub fn get_root_proof_outputs(&self) -> CityOpRootJobIds {
        CityOpRootJobIds {
            register_user_job_root_id: self
                .register_user_job_ids
                .last()
                .unwrap()
                .last()
                .unwrap()
                .get_output_id(),
            claim_deposit_job_root_id: self
                .claim_deposit_job_ids
                .last()
                .unwrap()
                .last()
                .unwrap()
                .get_output_id(),
            token_transfer_job_root_id: self
                .token_transfer_job_ids
                .last()
                .unwrap()
                .last()
                .unwrap()
                .get_output_id(),
            add_withdrawal_job_root_id: self
                .add_withdrawal_job_ids
                .last()
                .unwrap()
                .last()
                .unwrap()
                .get_output_id(),
            process_withdrawal_job_root_id: self
                .process_withdrawal_job_ids
                .last()
                .unwrap()
                .last()
                .unwrap()
                .get_output_id(),
            add_deposit_job_root_id: self
                .add_deposit_job_ids
                .last()
                .unwrap()
                .last()
                .unwrap()
                .get_output_id(),
        }
    }
}
impl CityOpJobIds {
    pub fn new() -> Self {
        Self {
            register_user_job_ids: Vec::new(),
            claim_deposit_job_ids: Vec::new(),
            token_transfer_job_ids: Vec::new(),
            add_withdrawal_job_ids: Vec::new(),

            process_withdrawal_job_ids: Vec::new(),
            add_deposit_job_ids: Vec::new(),
        }
    }
}
