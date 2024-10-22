use city_crypto::hash::{
    base_types::{hash160::Hash160, hash256::Hash256},
    qhashout::QHashOut,
};
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityTokenTransferRPCRequest {
    pub user_id: u64,
    pub to: u64,
    pub value: u64,
    pub nonce: u64,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityClaimDepositRPCRequest {
    pub user_id: u64,
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
pub struct CityAddWithdrawalRPCRequest {
    pub user_id: u64,
    pub value: u64,
    pub nonce: u64,

    pub destination_type: u8,
    pub destination: Hash160,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound = "")]
#[serde(transparent)]
pub struct CityRegisterUserRPCRequest<F: RichField> {
    pub public_key: QHashOut<F>,
}

impl<F: RichField> CityRegisterUserRPCRequest<F> {
    pub fn new_batch(public_keys: &[QHashOut<F>]) -> Vec<Self> {
        public_keys
            .iter()
            .map(|pk| CityRegisterUserRPCRequest { public_key: *pk })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
#[serde(untagged)]
pub enum CityRPCRequest<F: RichField> {
    CityTokenTransferRPCRequest((u32, CityTokenTransferRPCRequest)),
    CityClaimDepositRPCRequest((u32, CityClaimDepositRPCRequest)),
    CityAddWithdrawalRPCRequest((u32, CityAddWithdrawalRPCRequest)),
    CityRegisterUserRPCRequest((u32, CityRegisterUserRPCRequest<F>)),
}
