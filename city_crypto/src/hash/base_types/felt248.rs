use plonky2::hash::hash_types::{HashOut, RichField};

use super::hash256::Hash256;

// we only clear the top bit, so HASH_248_FELT_MASK = ((1u64<<63u64)-1u64)
const HASH_248_FELT_MASK: u64 = 0xffffffffffffffu64;
pub fn hashout_to_felt248_hashout<F: RichField>(hash: HashOut<F>) -> HashOut<F> {
    let a = hash.elements[0].to_canonical_u64();
    let b = hash.elements[1].to_canonical_u64();
    let c = hash.elements[2].to_canonical_u64();
    let d = hash.elements[3].to_canonical_u64() & HASH_248_FELT_MASK;
    HashOut {
        elements: [
            F::from_canonical_u64(a),
            F::from_canonical_u64(b),
            F::from_canonical_u64(c),
            F::from_canonical_u64(d),
        ],
    }
}
pub fn hash256_le_to_felt248_hashout<F: RichField>(hash: &[u8]) -> HashOut<F> {
    let a = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    let b = u64::from_le_bytes(hash[8..16].try_into().unwrap());
    let c = u64::from_le_bytes(hash[16..24].try_into().unwrap());
    let d = u64::from_le_bytes(hash[24..32].try_into().unwrap()) & HASH_248_FELT_MASK;
    HashOut {
        elements: [
            F::from_noncanonical_u64(a),
            F::from_noncanonical_u64(b),
            F::from_noncanonical_u64(c),
            F::from_noncanonical_u64(d),
        ],
    }
}
pub fn felt248_hashout_to_hash256_le<F: RichField>(hash: HashOut<F>) -> Hash256 {
    //let top_bit = 1u64 << 63u64;
    let a = hash.elements[0].to_canonical_u64();
    let b = hash.elements[1].to_canonical_u64();
    let c = hash.elements[2].to_canonical_u64();
    let d = hash.elements[3].to_canonical_u64() & HASH_248_FELT_MASK;

    let mut hash: [u8; 32] = [0; 32];
    hash[0..8].copy_from_slice(&a.to_le_bytes());
    hash[8..16].copy_from_slice(&b.to_le_bytes());
    hash[16..24].copy_from_slice(&c.to_le_bytes());
    hash[24..32].copy_from_slice(&d.to_le_bytes());
    Hash256(hash)
}