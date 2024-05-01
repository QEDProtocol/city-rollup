use std::fmt::Display;

use hex::FromHexError;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
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
}

impl Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl Hash160 {}

pub type MerkleProof160 = MerkleProofCore<Hash160>;
pub type DeltaMerkleProof160 = DeltaMerkleProofCore<Hash160>;
