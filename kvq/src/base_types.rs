use city_macros::impl_kvq_serialize;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::RichField;

use super::traits::KVQSerializable;

impl_kvq_serialize!(u8, u32, u64, u128);

impl<const SIZE: usize> KVQSerializable for [u8; SIZE] {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_vec())
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut result = [0u8; SIZE];
        result.copy_from_slice(bytes);
        Ok(result)
    }
}

impl KVQSerializable for Vec<u8> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.clone())
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bytes.to_vec())
    }
}
impl<const SIZE: usize> KVQSerializable for [u64; SIZE] {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(SIZE * 8);
        for i in 0..SIZE {
            result.extend_from_slice(&self[i].to_be_bytes());
        }
        Ok(result)
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut result = [0u64; SIZE];
        for i in 0..SIZE {
            let mut bytes_u64 = [0u8; 8];
            bytes_u64.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            result[i] = u64::from_be_bytes(bytes_u64);
        }
        Ok(result)
    }
}

impl<const SIZE: usize> KVQSerializable for [u32; SIZE] {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(SIZE * 4);
        for i in 0..SIZE {
            result.extend_from_slice(&self[i].to_be_bytes());
        }
        Ok(result)
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut result = [0u32; SIZE];
        for i in 0..SIZE {
            let mut bytes_u32 = [0u8; 4];
            bytes_u32.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
            result[i] = u32::from_be_bytes(bytes_u32);
        }
        Ok(result)
    }
}

impl<F: RichField> KVQSerializable for HashOut<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&self.elements[0].to_canonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&self.elements[1].to_canonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&self.elements[2].to_canonical_u64().to_le_bytes());
        result[24..32].copy_from_slice(&self.elements[3].to_canonical_u64().to_le_bytes());
        Ok(result.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[0..8]);
        let a = F::from_noncanonical_u64(u64::from_le_bytes(buf));
        buf.copy_from_slice(&bytes[8..16]);
        let b = F::from_noncanonical_u64(u64::from_le_bytes(buf));
        buf.copy_from_slice(&bytes[16..24]);
        let c = F::from_noncanonical_u64(u64::from_le_bytes(buf));
        buf.copy_from_slice(&bytes[24..32]);
        let d = F::from_noncanonical_u64(u64::from_le_bytes(buf));
        Ok(HashOut {
            elements: [a, b, c, d],
        })
    }
}
