use ripemd::Digest;
use ripemd::Ripemd160;

use crate::hash::base_types::hash160::Hash160;
use crate::hash::traits::hasher::MerkleHasher;

#[derive(Debug, Clone)]
pub struct CoreRipemd160Hasher {
    hasher: Ripemd160,
}

impl CoreRipemd160Hasher {
    pub fn hash_bytes(bytes: &[u8]) -> Hash160 {
        let mut hasher = Ripemd160::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Hash160(result.into())
    }
    pub fn new() -> Self {
        Self {
            hasher: Ripemd160::new(),
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }
    pub fn finalize(self) -> Hash160 {
        let result = self.hasher.finalize();
        Hash160(result.into())
    }
    pub fn finalize_reset(&mut self) -> Hash160 {
        let result = self.hasher.finalize_reset();
        Hash160(result.into())
    }
}

impl MerkleHasher<Hash160> for CoreRipemd160Hasher {
    fn two_to_one(left: &Hash160, right: &Hash160) -> Hash160 {
        let mut hasher = Ripemd160::new();
        hasher.update(left.0);
        hasher.update(right.0);
        let result = hasher.finalize();
        Hash160(result.into())
    }
}
