use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::{
    api::data::{
        block::rpc_request::{
            CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest, CityRegisterUserRPCRequest,
            CityTokenTransferRPCRequest,
        },
        store::CityL1Deposit,
    },
    introspection::transaction::BTCTransaction,
};
use plonky2::hash::hash_types::RichField;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DebugScenarioUserBalance<F: RichField> {
    pub private_key: QHashOut<F>,
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DebugScenarioSetup<F: RichField> {
    pub users: Vec<DebugScenarioUserBalance<F>>,
    pub l1_deposits: Vec<CityL1Deposit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DebugScenarioRPCRequestedActions<F: RichField> {
    pub last_block_spend_index: i32,
    pub funding_transactions: Vec<BTCTransaction>,
    pub register_users: Vec<CityRegisterUserRPCRequest<F>>,
    pub token_transfers: Vec<CityTokenTransferRPCRequest>,
    pub claim_l1_deposits: Vec<CityClaimDepositRPCRequest>,
    pub withdrawals: Vec<CityAddWithdrawalRPCRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SimpleDebugScenarioSetupPlan<F: RichField> {
    pub setup: DebugScenarioSetup<F>,
    pub rpc_requested_actions: DebugScenarioRPCRequestedActions<F>,
}
