use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use super::hash256bytes::Hash256BytesTarget;

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
