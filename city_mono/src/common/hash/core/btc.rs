use crate::common::base_types::hash::{hash160::Hash160, hash256::Hash256};

use super::{ripemd160::CoreRipemd160Hasher, sha256::CoreSha256Hasher};

pub fn btc_hash256(data: &[u8]) -> Hash256 {
  CoreSha256Hasher::hash_bytes(&CoreSha256Hasher::hash_bytes(data).0)
}

pub fn btc_hash160(data: &[u8]) -> Hash160 {
  CoreRipemd160Hasher::hash_bytes(&CoreSha256Hasher::hash_bytes(data).0)
}