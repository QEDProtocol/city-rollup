use city_crypto::hash::base_types::{hash160::Hash160, hash256::Hash256};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::introspection::transaction::{BTCTransaction, BTCTransactionOutput};

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
pub struct PartialBTCUTXO {
    pub txid: Hash256,
    pub value: u64,
    pub vout: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BTCTransactionWithVout {
    pub transaction: BTCTransaction,
    pub vout: u32,
}

impl From<BTCUTXO> for PartialBTCUTXO {
    fn from(utxo: BTCUTXO) -> Self {
        Self {
            txid: utxo.txid,
            value: utxo.value,
            vout: utxo.vout,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct BTCOutpoint {
    pub txid: Hash256,
    pub vout: u32,
}

#[derive(
    Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord,
)]
#[repr(u8)]
pub enum BTCAddressType {
    P2PKH = 0,
    P2SH = 1,
}
impl BTCAddressType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<BTCAddressType> for u8 {
    fn from(value: BTCAddressType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for BTCAddressType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BTCAddressType::P2PKH),
            1 => Ok(BTCAddressType::P2SH),
            _ => Err(anyhow::format_err!(
                "Invalid BTCAddressType type: {}",
                value
            )),
        }
    }
}

pub trait AddressToBTCScript {
    fn to_btc_script(&self) -> Vec<u8>;

    fn to_btc_output(&self, value: u64) -> BTCTransactionOutput {
        BTCTransactionOutput {
            value,
            script: self.to_btc_script(),
        }
    }
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct BTCAddress160 {
    pub address_type: BTCAddressType,
    pub address: Hash160,
}

impl BTCAddress160 {
    pub fn new_p2pkh(address: Hash160) -> Self {
        Self {
            address_type: BTCAddressType::P2PKH,
            address,
        }
    }
    pub fn new_p2sh(address: Hash160) -> Self {
        Self {
            address_type: BTCAddressType::P2PKH,
            address,
        }
    }
}

impl AddressToBTCScript for BTCAddress160 {
    fn to_btc_script(&self) -> Vec<u8> {
        match self.address_type {
            BTCAddressType::P2PKH => gen_p2pkh_script(&self.address).to_vec(),
            BTCAddressType::P2SH => gen_p2sh_script(&self.address).to_vec(),
        }
    }
}

pub fn gen_p2sh_script(hash: &Hash160) -> [u8; 23] {
    [
        0xa9, 0x14, hash.0[0], hash.0[1], hash.0[2], hash.0[3], hash.0[4], hash.0[5], hash.0[6],
        hash.0[7], hash.0[8], hash.0[9], hash.0[10], hash.0[11], hash.0[12], hash.0[13],
        hash.0[14], hash.0[15], hash.0[16], hash.0[17], hash.0[18], hash.0[19], 0x87,
    ]
}

pub fn gen_p2pkh_script(hash: &Hash160) -> [u8; 25] {
    [
        0x76, 0xa9, 0x14, hash.0[0], hash.0[1], hash.0[2], hash.0[3], hash.0[4], hash.0[5],
        hash.0[6], hash.0[7], hash.0[8], hash.0[9], hash.0[10], hash.0[11], hash.0[12], hash.0[13],
        hash.0[14], hash.0[15], hash.0[16], hash.0[17], hash.0[18], hash.0[19], 0x88, 0xac,
    ]
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct BTCAddress160WithValue {
    pub address: BTCAddress160,
    pub value: u64,
}
