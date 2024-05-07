use std::marker::PhantomData;

use city_rollup_common::{
    api::data::block::{
        requested_actions::{
            CityAddDepositRequest, CityAddWithdrawalRequest, CityClaimDepositRequest,
            CityProcessWithdrawalRequest, CityRegisterUserRequest, CityTokenTransferRequest,
        },
        rpc_request::{
            CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest, CityRegisterUserRPCRequest,
            CityTokenTransferRPCRequest,
        },
    },
    introspection::transaction::BTCTransaction,
    qworker::{
        job_id::{ProvingJobCircuitType, QJobTopic, QProvingJobDataID},
        proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync, QProofStoreWriterSync},
    },
};
use kvq::traits::KVQBinaryStore;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DebugScenarioRequestedActions<F: RichField> {
    pub token_transfers: Vec<CityTokenTransferRequest>,
    pub register_users: Vec<CityRegisterUserRequest<F>>,
    pub claim_l1_deposits: Vec<CityClaimDepositRequest>,
    pub withdrawals: Vec<CityAddWithdrawalRequest>,
    pub processed_withdrawals: Vec<CityProcessWithdrawalRequest>,
    pub added_deposits: Vec<CityAddDepositRequest>,
}
impl<F: RichField> DebugScenarioRequestedActions<F> {
    pub fn new() -> Self {
        Self {
            token_transfers: Vec::new(),
            register_users: Vec::new(),
            claim_l1_deposits: Vec::new(),
            withdrawals: Vec::new(),
            processed_withdrawals: Vec::new(),
            added_deposits: Vec::new(),
        }
    }
}
