use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::hash256bytes::Hash256BytesTarget;

pub trait CircuitBuilderFelt252Hash<F: RichField + Extendable<D>, const D: usize> {
    fn hash256_bytes_to_felt252_hashout(&mut self, value: Hash256BytesTarget) -> HashOutTarget;
    fn hashout_to_felt252_hashout(&mut self, value: HashOutTarget) -> HashOutTarget;
    fn felt252_hashout_to_hash256_bytes(&mut self, value: HashOutTarget) -> Hash256BytesTarget;
    fn connect_full_hashout_to_felt252_hashout(
        &mut self,
        standard_hashout: HashOutTarget,
        felt252_hashout: HashOutTarget,
    );
    fn ensure_is_zero_or_top_bit(&mut self, value: Target);
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

    fn connect_full_hashout_to_felt252_hashout(
        &mut self,
        standard_hashout: HashOutTarget,
        felt252_hashout: HashOutTarget,
    ) {
        let subtracted: [Target; 4] = core::array::from_fn(|i| {
            self.sub(standard_hashout.elements[i], felt252_hashout.elements[i])
        });
        self.ensure_is_zero_or_top_bit(subtracted[0]);
        self.ensure_is_zero_or_top_bit(subtracted[1]);
        self.ensure_is_zero_or_top_bit(subtracted[2]);
        self.ensure_is_zero_or_top_bit(subtracted[3]);
    }

    fn ensure_is_zero_or_top_bit(&mut self, value: Target) {
        /*
        let difference = (F::ORDER - (1u64<<63u64);
        if value == difference then value*(value+difference) = 0
        if value == 0 then value*(value+difference) = 0
        */

        let difference = self.constant(F::from_canonical_u64(F::ORDER - (1u64 << 63u64)));
        let value_plus_difference = self.add(value, difference);
        let product = self.mul(value, value_plus_difference);
        let zero = self.zero();
        self.connect(product, zero);
    }
}
