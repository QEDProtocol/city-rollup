use city_common::binaryhelpers::bytes::CompressedPublicKey;
use city_crypto::hash::{
    base_types::{hash160::Hash160, hash256::Hash256},
    qhashout::QHashOut,
};
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::qworker::job_id::QProvingJobDataID;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityTokenTransferRequest {
    request_type: u8,
    pub user_id: u64,
    pub to: u64,
    pub value: u64,
    pub nonce: u64,
    pub signature_proof_id: QProvingJobDataID,
}
impl CityTokenTransferRequest {
    pub fn new(
        user_id: u64,
        to: u64,
        value: u64,
        nonce: u64,
        signature_proof_id: QProvingJobDataID,
    ) -> Self {
        Self {
            request_type: 0,
            user_id,
            to,
            value,
            nonce,
            signature_proof_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityClaimDepositRequest {
    request_type: u8,
    pub user_id: u64,
    pub nonce: u64,
    pub deposit_id: u32,
    pub value: u64,

    pub txid: Hash256,
    pub public_key: CompressedPublicKey,
    pub signature_proof_id: QProvingJobDataID,
}
impl CityClaimDepositRequest {
    pub fn new(
        user_id: u64,
        nonce: u64,
        deposit_id: u32,
        value: u64,
        txid: Hash256,
        public_key: [u8; 33],
        signature_proof_id: QProvingJobDataID,
    ) -> Self {
        Self {
            request_type: 1,
            user_id,
            nonce,
            deposit_id,
            value,
            txid,
            public_key: CompressedPublicKey(public_key),
            signature_proof_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityAddDepositRequest {
    request_type: u8,
    pub value: u64,
    pub txid: Hash256,
    pub public_key: CompressedPublicKey,
}
impl CityAddDepositRequest {
    pub fn new(value: u64, txid: Hash256, public_key: [u8; 33]) -> Self {
        Self {
            request_type: 2,
            value,
            txid,
            public_key: CompressedPublicKey(public_key),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityAddWithdrawalRequest {
    request_type: u8,
    pub user_id: u64,
    pub value: u64,
    pub nonce: u64,

    pub destination_type: u8,
    pub destination: Hash160,
    pub signature_proof_id: QProvingJobDataID,
}

impl CityAddWithdrawalRequest {
    pub fn new(
        user_id: u64,
        value: u64,
        nonce: u64,
        destination_type: u8,
        destination: Hash160,
        signature_proof_id: QProvingJobDataID,
    ) -> Self {
        Self {
            request_type: 3,
            user_id,
            value,
            nonce,
            destination_type,
            destination,
            signature_proof_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CityProcessWithdrawalRequest {
    request_type: u8,
    pub withdrawal_id: u64,
}

impl CityProcessWithdrawalRequest {
    pub fn new(withdrawal_id: u64) -> Self {
        Self {
            request_type: 4,
            withdrawal_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityRegisterUserRequest<F: RichField> {
    request_type: u8,
    pub public_key: QHashOut<F>,
}

impl<F: RichField> CityRegisterUserRequest<F> {
    pub fn new(public_key: QHashOut<F>) -> Self {
        Self {
            request_type: 5,
            public_key,
        }
    }
}
