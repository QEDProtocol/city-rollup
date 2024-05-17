use city_crypto::hash::base_types::hash256::Hash256;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct BTCUTXOStatus {
    pub block_hash: Hash256,
    pub block_height: u64,
    pub block_time: u64,
    pub confirmed: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct BTCUTXO {
    pub status: BTCUTXOStatus,
    pub txid: Hash256,
    pub value: u64,
    pub vout: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct BTCOutpoint {
    pub txid: Hash256,
    pub vout: u32,
}
