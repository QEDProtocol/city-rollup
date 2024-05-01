use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::common::base_types::hash::{hash160::Hash160, hash256::Hash256};
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityTokenTransferRequest {
    pub user_id: u64,
    pub to: u64,
    pub value: u64,
    pub nonce: u64,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityClaimDepositRequest {
    pub user_id: u64,
    pub nonce: u64,
    pub deposit_id: u64,
    pub value: u64,

    pub txid: Hash256,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub public_key: [u8; 33],

    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityAddDepositRequest {
    pub value: u64,
    pub txid: Hash256,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub public_key: [u8; 33],
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityAddWithdrawalRequest {
    pub user_id: u64,
    pub value: u64,
    pub nonce: u64,

    pub destination_type: u8,
    pub destination: Hash160,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedBlock {
    pub current_script_hash: Hash160,
}
