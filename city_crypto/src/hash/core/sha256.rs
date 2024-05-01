use sha2::{Digest, Sha256};

use crate::hash::{base_types::hash256::Hash256, traits::hasher::MerkleHasher};

#[derive(Debug, Clone)]
pub struct CoreSha256Hasher {
    hasher: Sha256,
}

impl CoreSha256Hasher {
    pub fn hash_bytes(bytes: &[u8]) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Hash256(result.into())
    }
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }
    pub fn finalize(self) -> Hash256 {
        let result = self.hasher.finalize();
        Hash256(result.into())
    }
    pub fn finalize_reset(&mut self) -> Hash256 {
        let result = self.hasher.finalize_reset();
        Hash256(result.into())
    }
}

impl MerkleHasher<Hash256> for CoreSha256Hasher {
    fn two_to_one(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        let result = hasher.finalize();
        Hash256(result.into())
    }
}
