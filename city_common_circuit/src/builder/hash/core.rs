use city_crypto::hash::qhashout::QHashOut;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::builder::select::CircuitBuilderSelectHelpers;
use crate::hash::base_types::hash256::Hash256Target;
use crate::u32::arithmetic_u32::U32Target;

const NUM_HASH_OUT_ELEMENTS: usize = 4;
pub trait CircuitBuilderHashCore<F: RichField + Extendable<D>, const D: usize> {
    fn ensure_hash_is_zero(&mut self, hash: HashOutTarget);
    fn ensure_hash_is_non_zero(&mut self, hash: HashOutTarget);
    fn constant_whash(&mut self, value: QHashOut<F>) -> HashOutTarget;
    fn constant_hash_str(&mut self, value: &str) -> HashOutTarget;
    fn hashout_to_hash256_le(&mut self, value: HashOutTarget) -> Hash256Target;
    fn two_to_one_swapped<H: AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
        swap: BoolTarget,
    ) -> HashOutTarget;
    fn hash_two_to_one<H: AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget;
    fn ensure_hash_not_equal(&mut self, x: HashOutTarget, y: HashOutTarget);
    fn ensure_hash_not_equal_if(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    );
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashCore<F, D>
    for CircuitBuilder<F, D>
{
    /*fn constant_hash(&mut self, value: HashOut<F>) -> HashOutTarget {
        let a = self.cons
    }*/

    fn constant_whash(&mut self, value: QHashOut<F>) -> HashOutTarget {
        self.constant_hash(value.0)
    }

    fn constant_hash_str(&mut self, value: &str) -> HashOutTarget {
        self.constant_whash(QHashOut::from_string_or_panic(value))
    }

    fn two_to_one_swapped<H: AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
        swap: BoolTarget,
    ) -> HashOutTarget {
        let zero = self.zero();
        let mut state = H::AlgebraicPermutation::new(std::iter::repeat(zero));

        state.set_from_slice(&left.elements, 0);
        state.set_from_slice(&right.elements, NUM_HASH_OUT_ELEMENTS);
        state = H::permute_swapped(state, swap, self);

        HashOutTarget {
            elements: state.squeeze()[0..NUM_HASH_OUT_ELEMENTS]
                .try_into()
                .unwrap(),
        }
    }

    fn hashout_to_hash256_le(&mut self, value: HashOutTarget) -> Hash256Target {
        let (a_low, a_high) = self.split_low_high(value.elements[0], 32, 64);
        let (b_low, b_high) = self.split_low_high(value.elements[1], 32, 64);
        let (c_low, c_high) = self.split_low_high(value.elements[2], 32, 64);
        let (d_low, d_high) = self.split_low_high(value.elements[3], 32, 64);

        [
            U32Target(a_low),
            U32Target(a_high),
            U32Target(b_low),
            U32Target(b_high),
            U32Target(c_low),
            U32Target(c_high),
            U32Target(d_low),
            U32Target(d_high),
        ]
    }

    fn hash_two_to_one<H: AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget {
        self.hash_n_to_hash_no_pad::<H>(vec![
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
        ])
    }

    fn ensure_hash_not_equal(&mut self, x: HashOutTarget, y: HashOutTarget) {
        let is_eq_target = self.is_equal_hash(x, y).target;
        let false_target = self._false().target;
        self.connect(is_eq_target, false_target);
    }

    fn ensure_hash_not_equal_if(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    ) {
        let is_eq = self.is_equal_hash(x, y);
        let is_eq_and_enabled_target = self.and(is_eq, condition).target;
        let false_target = self._false().target;
        self.connect(is_eq_and_enabled_target, false_target);
    }

    fn ensure_hash_is_zero(&mut self, hash: HashOutTarget) {
        let zero_hash = self.constant_hash(HashOut::ZERO);
        self.connect_hashes(hash, zero_hash);
    }

    fn ensure_hash_is_non_zero(&mut self, hash: HashOutTarget) {
        let zero_hash = self.constant_hash(HashOut::ZERO);
        self.ensure_hash_not_equal(hash, zero_hash)
    }
}
