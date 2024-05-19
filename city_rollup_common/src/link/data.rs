use std::str::FromStr;

use city_crypto::hash::base_types::{
    hash160::{Hash160, P2PKH_ADDRESS_CHECK58_VERSION, P2SH_ADDRESS_CHECK58_VERSION},
    hash256::Hash256,
};
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
    pub fn to_version_byte(&self) -> u8 {
        match self {
            BTCAddressType::P2PKH => P2PKH_ADDRESS_CHECK58_VERSION,
            BTCAddressType::P2SH => P2SH_ADDRESS_CHECK58_VERSION,
        }
    }
    pub fn try_from_version_byte(version_byte: u8) -> anyhow::Result<Self> {
        match version_byte {
            P2PKH_ADDRESS_CHECK58_VERSION => Ok(BTCAddressType::P2PKH),
            P2SH_ADDRESS_CHECK58_VERSION => Ok(BTCAddressType::P2SH),
            _ => Err(anyhow::format_err!(
                "Invalid BTCAddressType version byte: {}",
                version_byte
            )),
        }
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
    pub fn try_from_string(str: &str) -> anyhow::Result<Self> {
        let decoded = bs58::decode(str).with_check(None).into_vec()?;
        if decoded.len() != 21 {
            return Err(anyhow::format_err!(
                "Invalid BTC address length: {}",
                decoded.len()
            ));
        }
        let address_type = BTCAddressType::try_from_version_byte(decoded[0])?;
        let mut hash_160_bytes = [0u8; 20];
        hash_160_bytes.copy_from_slice(&decoded[1..]);
        Ok(Self {
            address_type,
            address: Hash160(hash_160_bytes),
        })
    }
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
    pub fn to_address_string(&self) -> String {
        bs58::encode(self.address.0)
            .with_check_version(self.address_type.to_version_byte())
            .into_string()
    }
}

impl TryFrom<&str> for BTCAddress160 {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        BTCAddress160::try_from_string(value)
    }
}
/*
impl From<&BTCAddress160> for String {
    fn from(value: &BTCAddress160) -> Self {
        value.to_address_string()
    }
}
*/
impl ToString for BTCAddress160 {
    fn to_string(&self) -> String {
        self.to_address_string()
    }
}

impl FromStr for BTCAddress160 {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BTCAddress160::try_from_string(s)
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
