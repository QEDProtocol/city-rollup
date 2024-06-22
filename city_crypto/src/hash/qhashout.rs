use std::{fmt::Display, str::FromStr};

use anyhow::ensure;
use kvq::traits::KVQSerializable;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    },
    hash::hash_types::{HashOut, RichField},
    plonk::config::GenericHashOut,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;

use super::base_types::{
    felt248::felt248_hashout_to_hash256_le, felt252::{felt252_hashout_to_hash256_le, hashout_to_felt252_hashout}, hash256::Hash256
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QHashOut<F: Field>(pub HashOut<F>);
pub type GoldilocksHashOut = QHashOut<GoldilocksField>;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SerializableHashOut(#[serde_as(as = "serde_with::hex::Hex")] pub Vec<u8>);

impl<F: RichField> Serialize for QHashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = GenericHashOut::to_bytes(&self.0); // little endian
        bytes.reverse(); // big endian
        let raw = SerializableHashOut(bytes);

        raw.serialize(serializer)
    }
}

impl<'de, F: RichField> Deserialize<'de> for QHashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SerializableHashOut::deserialize(deserializer)?;
        let mut bytes = raw.0;
        if bytes.len() > 32 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse(); // little endian
        bytes.resize(32, 0);

        Ok(QHashOut(<HashOut<F> as GenericHashOut<F>>::from_bytes(
            &bytes,
        )))
    }
}

impl<F: Field> Default for QHashOut<F> {
    fn default() -> Self {
        QHashOut(HashOut::ZERO)
    }
}

impl<F: Field> From<QHashOut<F>> for HashOut<F> {
    fn from(value: QHashOut<F>) -> Self {
        value.0
    }
}
impl<F: Field> From<HashOut<F>> for QHashOut<F> {
    fn from(value: HashOut<F>) -> Self {
        QHashOut(value)
    }
}

impl<F: RichField> TryFrom<&[F]> for QHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[F]) -> Result<Self, Self::Error> {
        ensure!(elements.len() == 4);
        Ok(Self(HashOut {
            elements: elements.try_into().unwrap(),
        }))
    }
}

impl<F: RichField> TryFrom<&[u64; 4]> for QHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[u64; 4]) -> Result<Self, Self::Error> {
        Ok(Self(HashOut {
            elements: [
                F::from_noncanonical_u64(elements[0]),
                F::from_noncanonical_u64(elements[1]),
                F::from_noncanonical_u64(elements[2]),
                F::from_noncanonical_u64(elements[3]),
            ],
        }))
    }
}
impl<F: RichField> Display for QHashOut<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for QHashOut<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

impl<F: RichField> GenericHashOut<F> for QHashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        GenericHashOut::to_bytes(&self.0)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        QHashOut(<HashOut<F> as GenericHashOut<F>>::from_bytes(bytes))
    }

    fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}
impl<F: RichField> QHashOut<F> {
    pub const ZERO: Self = Self(HashOut::<F>::ZERO);

    pub fn from_string_or_panic(s: &str) -> Self {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json).unwrap()
    }
    pub fn rand() -> Self {
        Self(HashOut::rand())
    }
    pub fn from_values(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(a),
                F::from_noncanonical_u64(b),
                F::from_noncanonical_u64(c),
                F::from_noncanonical_u64(d),
            ],
        })
    }
    pub fn from_felt_slice(slice: &[F]) -> Self {
        Self(HashOut {
            elements: [slice[0], slice[1], slice[2], slice[3]],
        })
    }
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&self.0.elements[0].to_canonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&self.0.elements[1].to_canonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&self.0.elements[2].to_canonical_u64().to_le_bytes());
        result[24..32].copy_from_slice(&self.0.elements[3].to_canonical_u64().to_le_bytes());
        result
    }
    pub fn to_felt252_hash256(&self) -> Hash256 {
        felt252_hashout_to_hash256_le(hashout_to_felt252_hashout(self.0))
    }
    pub fn to_felt248_hash256(&self) -> Hash256 {
        felt248_hashout_to_hash256_le(self.0)
    }
    pub fn from_hash256_le(hash: Hash256) -> Self {
        let u64_x4 = hash.to_le_u64_x4();
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(u64_x4[0]),
                F::from_noncanonical_u64(u64_x4[1]),
                F::from_noncanonical_u64(u64_x4[2]),
                F::from_noncanonical_u64(u64_x4[3]),
            ],
        })
    }
    pub fn to_string_le(&self) -> String {
        hex::encode(self.to_le_bytes())
    }
}



impl<F: RichField> KVQSerializable for QHashOut<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        KVQSerializable::to_bytes(&self.0)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(QHashOut(<HashOut<F> as KVQSerializable>::from_bytes(
            bytes,
        )?))
    }
}
