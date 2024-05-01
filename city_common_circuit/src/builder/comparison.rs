use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::u32::multiple_comparison::list_lte_circuit;

pub trait CircuitBuilderComparison<F: RichField + Extendable<D>, const D: usize> {
    fn is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_less_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;

    fn enforce_is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target);
    fn enforce_is_less_than(&mut self, num_bits: usize, x: Target, y: Target);
    fn enforce_is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target);
    fn enforce_is_greater_than(&mut self, num_bits: usize, x: Target, y: Target);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderComparison<F, D>
    for CircuitBuilder<F, D>
{
    fn is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        list_lte_circuit(self, vec![x], vec![y], num_bits)
    }

    fn is_less_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        let is_lte = self.is_less_than_or_equal(num_bits, x, y);
        let is_equal = self.is_equal(x, y);
        let is_not_equal = self.not(is_equal);
        self.and(is_lte, is_not_equal)
    }

    fn is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        let is_gt = self.is_greater_than(num_bits, x, y);
        let is_equal = self.is_equal(x, y);
        self.or(is_gt, is_equal)
    }

    fn is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        let is_lte = self.is_less_than_or_equal(num_bits, x, y);
        self.not(is_lte)
    }

    fn enforce_is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_less_than_or_equal(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn enforce_is_less_than(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_less_than(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn enforce_is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_greater_than_or_equal(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn enforce_is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_greater_than(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }
}
