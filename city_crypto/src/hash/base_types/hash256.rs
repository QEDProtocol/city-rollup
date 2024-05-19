use std::fmt::Display;

use hex::FromHexError;
use kvq::traits::KVQSerializable;
use plonky2::{field::secp256k1_scalar::Secp256K1Scalar, hash::hash_types::RichField};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    hash::{
        merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
        qhashout::QHashOut,
    },
    signature::secp256k1::curve::{ecdsa::ECDSASecretKey, secp256k1::Secp256K1},
};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);
impl Default for Hash256 {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

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
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
    pub fn reversed(&self) -> Self {
        Hash256(core::array::from_fn(|i| self.0[31 - i]))
    }
}

impl From<Hash256> for ECDSASecretKey<Secp256K1> {
    fn from(value: Hash256) -> Self {
        let u64_result: [u64; 4] = core::array::from_fn(|i| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&value.0[i * 8..(i + 1) * 8]);
            u64::from_le_bytes(bytes)
        });
        let scalar = Secp256K1Scalar(u64_result);
        ECDSASecretKey(scalar)
    }
}

impl From<Hash256> for k256::ecdsa::SigningKey {
    fn from(value: Hash256) -> Self {
        Self::from_slice(&value.0).unwrap()
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

impl KVQSerializable for Hash256 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!(
                "expected 32 bytes for deserializing Hash256, got {} bytes",
                bytes.len()
            );
        }
        let mut inner_data = [0u8; 32];
        inner_data.copy_from_slice(bytes);
        Ok(Hash256(inner_data))
    }
}

impl<F: RichField> From<QHashOut<F>> for Hash256 {
    fn from(value: QHashOut<F>) -> Self {
        let mut data = [0u8; 32];
        for i in 0..4 {
            let u64 = value.0.elements[i].to_canonical_u64();
            data[i * 8..(i + 1) * 8].copy_from_slice(&u64.to_le_bytes());
        }
        Self(data)
    }
}
