use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::hash::base_types::hash256bytes::Hash256BytesTarget;

pub trait CircuitBuilderSelectHelpers<F: RichField + Extendable<D>, const D: usize> {
    fn select_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: Target,
        false_value: Target,
    ) -> Target;
    fn select_hash(
        &mut self,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget;
    fn pick_from_hashes(
        &mut self,
        value: HashOutTarget,
        allowed_hashes: &[HashOutTarget],
    ) -> HashOutTarget;
    fn select_hash_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget;

    fn is_equal_hash(
        &mut self,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> BoolTarget;
    fn is_equal_hash_256_bytes(
        &mut self,
        x: Hash256BytesTarget,
        y: Hash256BytesTarget,
    ) -> BoolTarget;
    fn is_equal_array(&mut self, x: &[Target], y: &[Target]) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSelectHelpers<F, D>
    for CircuitBuilder<F, D>
{
    fn select_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: Target,
        false_value: Target,
    ) -> Target {
        let not_zero = self.not(zero_condition);
        let value = self.select(condition, true_value, false_value);
        self.mul(not_zero.target, value)
    }

    fn select_hash(
        &mut self,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget {
        HashOutTarget {
            elements: core::array::from_fn(|i| {
                self.select(condition, true_value.elements[i], false_value.elements[i])
            }),
        }
    }

    fn select_hash_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget {
        let base = self.select_hash(condition, true_value, false_value);
        let not_zero = self.not(zero_condition).target;
        HashOutTarget {
            elements: core::array::from_fn(|i: usize| self.mul(not_zero, base.elements[i])),
        }
    }
    fn is_equal_hash(&mut self, x: HashOutTarget, y: HashOutTarget) -> BoolTarget {
        let mut result = self.constant_bool(true);
        for i in 0..x.elements.len() {
            let equal = self.is_equal(x.elements[i], y.elements[i]);
            result = self.and(equal, result);
        }
        result
    }

    fn pick_from_hashes(
        &mut self,
        value: HashOutTarget,
        allowed_hashes: &[HashOutTarget],
    ) -> HashOutTarget {
        if allowed_hashes.len() == 0 {
            panic!("must pass at least one hash to select_from_hashes");
        }
        let mut last_allowed = allowed_hashes[0];

        for i in 1..allowed_hashes.len() {
            let equal = self.is_equal_hash(value, allowed_hashes[i]);
            last_allowed = self.select_hash(equal, value, last_allowed);
        }
        last_allowed
    }

    fn is_equal_hash_256_bytes(
        &mut self,
        x: Hash256BytesTarget,
        y: Hash256BytesTarget,
    ) -> BoolTarget {
        self.is_equal_array(&x, &y)
    }

    fn is_equal_array(&mut self, x: &[Target], y: &[Target]) -> BoolTarget {
        let mut result = self.constant_bool(true);
        for i in 0..x.len() {
            let equal = self.is_equal(x[i], y[i]);
            result = self.and(equal, result);
        }
        result
    }
}
