use std::fmt::Display;

use hex::FromHexError;
use kvq::traits::KVQSerializable;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};

pub const P2SH_ADDRESS_CHECK58_VERSION: u8 = 0xc4;
pub const P2PKH_ADDRESS_CHECK58_VERSION: u8 = 0x6f;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Hash, Eq, Ord, PartialOrd)]
pub struct Hash160(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 20]);

impl Hash160 {
    /// .
    ///
    /// # Panics
    ///
    /// Panics if .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 20);
        let mut array = [0u8; 20];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn to_check_base58(&self, version: u8) -> String {
        bs58::encode(&self.0)
            .with_check_version(version)
            .into_string()
    }
    pub fn to_p2sh_address(&self) -> String {
        bs58::encode(&self.0)
            .with_check_version(P2SH_ADDRESS_CHECK58_VERSION)
            .into_string()
    }
    pub fn to_p2pkh_address(&self) -> String {
        bs58::encode(&self.0)
            .with_check_version(P2PKH_ADDRESS_CHECK58_VERSION)
            .into_string()
    }
}

impl Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl KVQSerializable for Hash160 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 20 {
            anyhow::bail!(
                "expected 20 bytes for deserializing Hash160, got {} bytes",
                bytes.len()
            );
        }
        let mut inner_data = [0u8; 20];
        inner_data.copy_from_slice(bytes);
        Ok(Hash160(inner_data))
    }
}

pub type MerkleProof160 = MerkleProofCore<Hash160>;
pub type DeltaMerkleProof160 = DeltaMerkleProofCore<Hash160>;
