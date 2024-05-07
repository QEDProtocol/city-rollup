use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct CompressedPublicKey(pub [u8; 33]);

impl Serialize for CompressedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct ByteArrayVisitor;

impl<'de> Visitor<'de> for ByteArrayVisitor {
    type Value = [u8; 33];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of 33 bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() == 33 {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(v);
            Ok(arr)
        } else {
            Err(E::invalid_length(v.len(), &self))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut arr = [0u8; 33];
        for (i, place) in arr.iter_mut().enumerate() {
            *place = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        Ok(arr)
    }
}

impl<'de> Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(CompressedPublicKey(
            deserializer.deserialize_bytes(ByteArrayVisitor)?,
        ))
    }
}

pub fn bytes_to_u32_vec_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let b = chunk.try_into().unwrap_or([0u8; 4]);
            u32::from_le_bytes(b)
        })
        .collect()
}
pub fn bytes_to_u32_vec_be(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let b = chunk.try_into().unwrap_or([0u8; 4]);
            u32::from_be_bytes(b)
        })
        .collect()
}
pub fn u32_vec_to_bytes_be(u32s: &[u32]) -> Vec<u8> {
    u32s.iter()
        .flat_map(|&u| u.to_be_bytes().to_vec())
        .collect()
}

#[inline]
pub fn read_u32_be_at(array: &[u8], index: usize) -> u32 {
    ((array[index] as u32) << 24)
        + ((array[index + 1] as u32) << 16)
        + ((array[index + 2] as u32) << 8)
        + (array[index + 3] as u32)
}

#[inline]
pub fn read_u32_le_at(array: &[u8], index: usize) -> u32 {
    ((array[index + 3] as u32) << 24)
        + ((array[index + 2] as u32) << 16)
        + ((array[index + 1] as u32) << 8)
        + (array[index] as u32)
}

pub fn read_u48_from_bytes_le(bytes: &[u8], offset: usize) -> u64 {
    let mut result = 0u64;
    for i in 0..6 {
        result |= (bytes[offset + i] as u64) << (i * 8);
    }
    result
}

pub fn read_u56_from_bytes_le(bytes: &[u8], offset: usize) -> u64 {
    let mut result = 0u64;
    for i in 0..7 {
        result |= (bytes[offset + i] as u64) << (i * 8);
    }
    result
}
