pub use std::fmt::Display;

use hex::FromHexError;
use kvq::traits::KVQSerializable;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord)]
pub struct Serialized2DFeltBLS12381(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 48]);
impl Default for Serialized2DFeltBLS12381 {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

impl Serialized2DFeltBLS12381 {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 48);
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 48];
        rand::thread_rng().fill_bytes(&mut bytes);
        Serialized2DFeltBLS12381(bytes)
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
}

impl Display for Serialized2DFeltBLS12381 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&str> for Serialized2DFeltBLS12381 {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Serialized2DFeltBLS12381::from_hex_string(value)
    }
}
impl TryFrom<String> for Serialized2DFeltBLS12381 {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Serialized2DFeltBLS12381::from_hex_string(&value)
    }
}

impl KVQSerializable for Serialized2DFeltBLS12381 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 48 {
            anyhow::bail!(
                "expected 48 bytes for deserializing Serialized2DFeltBLS12381, got {} bytes",
                bytes.len()
            );
        }
        let mut inner_data = [0u8; 48];
        inner_data.copy_from_slice(bytes);
        Ok(Serialized2DFeltBLS12381(inner_data))
    }
}
