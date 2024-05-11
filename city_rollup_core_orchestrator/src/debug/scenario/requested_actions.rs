use city_rollup_common::{
    api::data::{
        block::requested_actions::{
            CityAddDepositRequest, CityAddWithdrawalRequest, CityClaimDepositRequest,
            CityProcessWithdrawalRequest, CityRegisterUserRequest, CityTokenTransferRequest,
        },
        store::CityL2BlockState,
    },
    introspection::transaction::BTCTransaction,
};
use kvq::traits::KVQBinaryStore;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

// use super::rpc_processor::CityScenarioRequestedActionsFromRPC;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityScenarioRequestedActions<F: RichField> {
    pub add_deposits: Vec<CityAddDepositRequest>,
    pub add_withdrawals: Vec<CityAddWithdrawalRequest>,
    pub claim_l1_deposits: Vec<CityClaimDepositRequest>,
    pub token_transfers: Vec<CityTokenTransferRequest>,
    pub process_withdrawals: Vec<CityProcessWithdrawalRequest>,
    pub register_users: Vec<CityRegisterUserRequest<F>>,
}
impl<F: RichField> CityScenarioRequestedActions<F> {
    pub fn new() -> Self {
        Self {
            add_deposits: Vec::new(),
            add_withdrawals: Vec::new(),
            claim_l1_deposits: Vec::new(),
            token_transfers: Vec::new(),
            process_withdrawals: Vec::new(),
            register_users: Vec::new(),
        }
    }
    // pub fn new_from_requested_rpc<S: KVQBinaryStore>(
    //     requested_from_rpc: CityScenarioRequestedActionsFromRPC<F>,
    //     funding_transactions: &[BTCTransaction],
    //     last_block_state: &CityL2BlockState,
    //     max_withdrawals_processed_per_block: usize,
    // ) -> Self {
    //     let last_block_pending_withdrawals =
    //         last_block_state.next_add_withdrawal_id - last_block_state.next_process_withdrawal_id;
    //     let total_pending_withdrawals_end =
    //         last_block_pending_withdrawals + requested_from_rpc.add_withdrawals.len() as u64;
    //     let total_withdrawals_to_process =
    //         total_pending_withdrawals_end.min(max_withdrawals_processed_per_block as u64);
    //     let process_withdrawals = (0..total_withdrawals_to_process)
    //         .map(|i| {
    //             let withdrawal_id = last_block_state.next_process_withdrawal_id + i;
    //             CityProcessWithdrawalRequest::new(withdrawal_id)
    //         })
    //         .collect();
    //     Self {
    //         add_deposits: funding_transactions
    //             .iter()
    //             .map(|tx| CityAddDepositRequest::new_from_transaction(tx))
    //             .collect(),
    //         add_withdrawals: requested_from_rpc.add_withdrawals,
    //         claim_l1_deposits: requested_from_rpc.claim_l1_deposits,
    //         token_transfers: requested_from_rpc.token_transfers,
    //         process_withdrawals,
    //         register_users: requested_from_rpc.register_users,
    //     }
    // }
}
