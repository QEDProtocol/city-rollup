use plonky2::hash::hash_types::{HashOut, RichField};

use crate::{common::QHashOut, store::kvq::traits::KVQSerializable};

impl<F: RichField> KVQSerializable for QHashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        QHashOut(HashOut::<F>::from_bytes(bytes))
    }
}

impl<F: RichField> KVQSerializable for HashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&self.elements[0].to_canonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&self.elements[1].to_canonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&self.elements[2].to_canonical_u64().to_le_bytes());
        result[24..32].copy_from_slice(&self.elements[3].to_canonical_u64().to_le_bytes());
        result.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        HashOut {
            elements: [
                F::from_noncanonical_u64(u64::from_le_bytes(bytes[0..8].try_into().unwrap())),
                F::from_noncanonical_u64(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
                F::from_noncanonical_u64(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
                F::from_noncanonical_u64(u64::from_le_bytes(bytes[24..32].try_into().unwrap())),
            ],
        }
    }
}
