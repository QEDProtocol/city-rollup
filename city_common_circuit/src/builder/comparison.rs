use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::u32::multiple_comparison::list_lte_circuit;

pub trait CircuitBuilderComparison<F: RichField + Extendable<D>, const D: usize> {
    fn is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_less_than_or_equal_split(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_less_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_not_equal(&mut self, x: Target, y: Target) -> BoolTarget;

    fn ensure_is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_is_less_than(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_is_greater_than(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_not_equal(&mut self, x: Target, y: Target);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderComparison<F, D>
    for CircuitBuilder<F, D>
{
    fn is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        //list_lte_circuit(self, vec![x], vec![y], num_bits)
        self.is_less_than_or_equal_split(num_bits, x, y)
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

    fn ensure_is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_less_than_or_equal(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn ensure_is_less_than(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_less_than(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn ensure_is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_greater_than_or_equal(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn ensure_is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_greater_than(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn is_not_equal(&mut self, x: Target, y: Target) -> BoolTarget {
        let is_eq = self.is_equal(x, y);
        self.not(is_eq)
    }

    fn ensure_not_equal(&mut self, x: Target, y: Target) {
        let is_eq = self.is_equal(x, y);
        let zero = self.zero();
        self.connect(is_eq.target, zero);
    }
    
    
    fn is_less_than_or_equal_split(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        if num_bits <= 32 {
            list_lte_circuit(self, vec![x], vec![y], num_bits)
        }else{
            // x_low = x & 0xffffffff, x_high = x >> 32
            let (x_low_target, x_high_target) = self.split_low_high(x, 32, 64);
            // y_low = x & 0xffffffff, y_high = y >> 32
            let (y_low_target, y_high_target) = self.split_low_high(y, 32, 64);

            // is_gt = (x_high > y_high) || (x_high == y_high && x_low > y_low)
            // is_leq = !is_gt

            // high_leq_target = (x_high <= y_high)
            let high_leq_target = list_lte_circuit(self, vec![x_high_target], vec![y_high_target], 32);

            // low_leq_target = (x_low <= y_low)
            let low_leq_target = list_lte_circuit(self, vec![x_low_target], vec![y_low_target], 32);

            // high_gt_target = (x_high > y_high) = !(x_high <= y_high)
            let high_gt_target = self.not(high_leq_target);

            // low_gt_target = (x_low > y_low) = !(x_low <= y_low)
            let low_gt_target = self.not(low_leq_target);

            // high_eq_target = x_high == y_high
            let high_eq_target = self.is_equal(x_high_target, y_high_target);

            // equal_high_bits_case_target = (x_high == y_high && x_low > y_low)
            let equal_high_bits_case_target = self.and(high_eq_target, low_gt_target);

            // is_gt = (x_high > y_high) || (x_high == y_high && x_low > y_low)

            let is_gt = self.or(high_gt_target, equal_high_bits_case_target);

            // is_leq = !is_gt = !((x_high > y_high) || (x_high == y_high && x_low > y_low))
            let is_leq = self.not(is_gt);
            is_leq
        }
    }
}
