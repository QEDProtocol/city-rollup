use plonky2::hash::hash_types::HashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::common::base_types::hash::hash256::Hash256;

use super::hash256bytes::Hash256BytesTarget;

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
pub fn felt252_hashout_to_hash256_le<F: RichField>(hash: HashOut<F>) -> Hash256 {
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
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
    };

    use crate::common::builder::hash::felthash252::felt252_hashout_to_hash256_le;

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
            felt252_hashout_to_hash256_le::<F>(ho1).to_hex_string()
        );
    }
}

pub trait CircuitBuilderFelt252Hash<F: RichField + Extendable<D>, const D: usize> {
    fn hash256_bytes_to_felt252_hashout(&mut self, value: Hash256BytesTarget) -> HashOutTarget;
    fn hashout_to_felt252_hashout(&mut self, value: HashOutTarget) -> HashOutTarget;
    fn felt252_hashout_to_hash256_bytes(&mut self, value: HashOutTarget) -> Hash256BytesTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderFelt252Hash<F, D>
    for CircuitBuilder<F, D>
{
    fn hash256_bytes_to_felt252_hashout(&mut self, value: Hash256BytesTarget) -> HashOutTarget {
        let results = value
            .iter()
            .flat_map(|v| self.split_le(*v, 8))
            .collect::<Vec<_>>();
        let r2 = results
            .chunks_exact(64)
            .map(|chunk| self.le_sum(chunk[0..63].iter()))
            .collect::<Vec<_>>();

        HashOutTarget {
            elements: [r2[0], r2[1], r2[2], r2[3]],
        }
    }

    fn hashout_to_felt252_hashout(&mut self, value: HashOutTarget) -> HashOutTarget {
        let a = self.split_low_high(value.elements[0], 63, 64).0;
        let b = self.split_low_high(value.elements[1], 63, 64).0;
        let c = self.split_low_high(value.elements[2], 63, 64).0;
        let d = self.split_low_high(value.elements[3], 63, 64).0;
        HashOutTarget {
            elements: [a, b, c, d],
        }
    }

    fn felt252_hashout_to_hash256_bytes(&mut self, value: HashOutTarget) -> Hash256BytesTarget {
        let bytes = value
            .elements
            .iter()
            .flat_map(|e| self.split_le(*e, 63))
            .collect::<Vec<BoolTarget>>()
            .chunks(8)
            .map(|bits| self.le_sum(bits.iter()))
            .collect::<Vec<_>>();
        core::array::from_fn(|i| bytes[i])
    }
}
