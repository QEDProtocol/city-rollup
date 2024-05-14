use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::RichField;

use super::hash256::Hash256;

// we only clear the top bit, so HASH_252_FELT_MASK = ((1u64<<63u64)-1u64)
const HASH_252_FELT_MASK: u64 = 0x7fffffffffffffffu64;
pub fn hashout_to_felt252_hashout<F: RichField>(hash: HashOut<F>) -> HashOut<F> {
    let a = hash.elements[0].to_canonical_u64() & HASH_252_FELT_MASK;
    let b = hash.elements[1].to_canonical_u64() & HASH_252_FELT_MASK;
    let c = hash.elements[2].to_canonical_u64() & HASH_252_FELT_MASK;
    let d = hash.elements[3].to_canonical_u64() & HASH_252_FELT_MASK;
    HashOut {
        elements: [
            F::from_canonical_u64(a),
            F::from_canonical_u64(b),
            F::from_canonical_u64(c),
            F::from_canonical_u64(d),
        ],
    }
}
pub fn hash256_le_to_felt252_hashout<F: RichField>(hash: &[u8]) -> HashOut<F> {
    let a = u64::from_le_bytes(hash[0..8].try_into().unwrap()) & HASH_252_FELT_MASK;
    let b = u64::from_le_bytes(hash[8..16].try_into().unwrap()) & HASH_252_FELT_MASK;
    let c = u64::from_le_bytes(hash[16..24].try_into().unwrap()) & HASH_252_FELT_MASK;
    let d = u64::from_le_bytes(hash[24..32].try_into().unwrap()) & HASH_252_FELT_MASK;
    HashOut {
        elements: [
            F::from_canonical_u64(a),
            F::from_canonical_u64(b),
            F::from_canonical_u64(c),
            F::from_canonical_u64(d),
        ],
    }
}
const fn u8_to_bits_le(value: u8) -> [u8; 8] {
    [
        (value >> 0) & 1,
        (value >> 1) & 1,
        (value >> 2) & 1,
        (value >> 3) & 1,
        (value >> 4) & 1,
        (value >> 5) & 1,
        (value >> 6) & 1,
        (value >> 7) & 1,
    ]
}
fn sum_le_bits(bits: &[u8]) -> u64 {
    bits.iter().fold(0u64, |acc, &b| (acc << 1) | (b as u64))
}
pub fn hash256_le_to_felt252_hashout_packed<F: RichField>(hash: &[u8]) -> HashOut<F> {
    let result = hash
        .iter()
        .map(|x| u8_to_bits_le(*x))
        .flatten()
        .collect::<Vec<_>>();
    let a = F::from_canonical_u64(sum_le_bits(&result[0..63]));
    let b = F::from_canonical_u64(sum_le_bits(&result[63..126]));
    let c = F::from_canonical_u64(sum_le_bits(&result[126..189]));
    let d = F::from_canonical_u64(sum_le_bits(&result[189..252]));
    HashOut {
        elements: [a, b, c, d],
    }
}
pub fn felt252_hashout_to_hash256_le<F: RichField>(hash: HashOut<F>) -> Hash256 {
    //let top_bit = 1u64 << 63u64;
    let a = hash.elements[0].to_canonical_u64() & HASH_252_FELT_MASK;
    let b = hash.elements[1].to_canonical_u64() & HASH_252_FELT_MASK;
    let c = hash.elements[2].to_canonical_u64() & HASH_252_FELT_MASK;
    let d = hash.elements[3].to_canonical_u64() & HASH_252_FELT_MASK;

    let mut hash: [u8; 32] = [0; 32];
    hash[0..8].copy_from_slice(&a.to_le_bytes());
    hash[8..16].copy_from_slice(&b.to_le_bytes());
    hash[16..24].copy_from_slice(&c.to_le_bytes());
    hash[24..32].copy_from_slice(&d.to_le_bytes());
    Hash256(hash)
}
pub fn felt252_hashout_to_hash256_le_packed<F: RichField>(hash: HashOut<F>) -> Hash256 {
    //let top_bit = 1u64 << 63u64;
    let a = hash.elements[0].to_canonical_u64() & HASH_252_FELT_MASK;
    let b = hash.elements[1].to_canonical_u64() & HASH_252_FELT_MASK;
    let c = hash.elements[2].to_canonical_u64() & HASH_252_FELT_MASK;
    let d = hash.elements[3].to_canonical_u64() & HASH_252_FELT_MASK;

    let x = a | ((b & 1u64) << 63u64);
    let y = (b >> 1u64) | ((c & 3u64) << 62u64);
    let z = (c >> 2u64) | ((d & 7u64) << 61u64);
    let w = d >> 3u64;

    let mut hash: [u8; 32] = [0; 32];
    hash[0..8].copy_from_slice(&x.to_le_bytes());
    hash[8..16].copy_from_slice(&y.to_le_bytes());
    hash[16..24].copy_from_slice(&z.to_le_bytes());
    hash[24..32].copy_from_slice(&w.to_le_bytes());
    Hash256(hash)
}
#[cfg(test)]
mod test {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::HashOut;

    use crate::hash::base_types::felt252::felt252_hashout_to_hash256_le_packed;

    #[test]
    fn test1() {
        type F = GoldilocksField;

        let ho1 = HashOut {
            elements: [
                F::from_noncanonical_u64(9223372036854775801u64),
                F::from_noncanonical_u64(9223372036854775792u64),
                F::from_noncanonical_u64(9223372036854775793u64),
                F::from_noncanonical_u64(6917529027641081855u64),
            ],
        };
        println!("ho: {:?}", ho1);
        println!(
            "252: {}:",
            felt252_hashout_to_hash256_le_packed::<F>(ho1).to_hex_string()
        );
    }
}
