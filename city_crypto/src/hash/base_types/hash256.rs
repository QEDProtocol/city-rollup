use std::fmt::Display;

use hex::FromHexError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct Hash256(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);

impl Hash256 {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Hash256(bytes)
    }
}

impl Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub type MerkleProof256 = MerkleProofCore<Hash256>;
pub type DeltaMerkleProof256 = DeltaMerkleProofCore<Hash256>;

impl TryFrom<&str> for Hash256 {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Hash256::from_hex_string(value)
    }
}
impl TryFrom<String> for Hash256 {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Hash256::from_hex_string(&value)
    }
}
