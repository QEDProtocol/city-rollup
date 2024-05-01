use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::AlgebraicHasher,
};
use serde::{Deserialize, Serialize};

use crate::common::{base_types::hash::hash256::Hash256, QHashOut};

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
