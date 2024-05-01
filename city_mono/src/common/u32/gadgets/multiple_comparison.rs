use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use city_common::math::ceil_div_usize;

use super::super::gadgets::arithmetic_u32::U32Target;
use super::super::gates::comparison::ComparisonGate;

/// Returns true if a is less than or equal to b, considered as base-`2^num_bits` limbs of a large value.
/// This range-checks its inputs.
pub fn list_lte_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Vec<Target>,
    b: Vec<Target>,
    num_bits: usize,
) -> BoolTarget {
    assert_eq!(
        a.len(),
        b.len(),
        "Comparison must be between same number of inputs and outputs"
    );
    let n = a.len();

    let chunk_bits = 2;
    let num_chunks = ceil_div_usize(num_bits, chunk_bits);

    let one = builder.one();
    let mut result = one;
    for i in 0..n {
        let a_le_b_gate = ComparisonGate::new(num_bits, num_chunks);
        let a_le_b_row = builder.add_gate(a_le_b_gate.clone(), vec![]);
        builder.connect(
            Target::wire(a_le_b_row, a_le_b_gate.wire_first_input()),
            a[i],
        );
        builder.connect(
            Target::wire(a_le_b_row, a_le_b_gate.wire_second_input()),
            b[i],
        );
        let a_le_b_result = Target::wire(a_le_b_row, a_le_b_gate.wire_result_bool());

        let b_le_a_gate = ComparisonGate::new(num_bits, num_chunks);
        let b_le_a_row = builder.add_gate(b_le_a_gate.clone(), vec![]);
        builder.connect(
            Target::wire(b_le_a_row, b_le_a_gate.wire_first_input()),
            b[i],
        );
        builder.connect(
            Target::wire(b_le_a_row, b_le_a_gate.wire_second_input()),
            a[i],
        );
        let b_le_a_result = Target::wire(b_le_a_row, b_le_a_gate.wire_result_bool());

        let these_limbs_equal = builder.mul(a_le_b_result, b_le_a_result);
        let these_limbs_less_than = builder.sub(one, b_le_a_result);
        result = builder.mul_add(these_limbs_equal, result, these_limbs_less_than);
    }

    // `result` being boolean is an invariant, maintained because its new value is always
    // `x * result + y`, where `x` and `y` are booleans that are not simultaneously true.
    BoolTarget::new_unsafe(result)
}

/// Helper function for comparing, specifically, lists of `U32Target`s.
pub fn list_lte_u32_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Vec<U32Target>,
    b: Vec<U32Target>,
) -> BoolTarget {
    let a_targets: Vec<Target> = a.iter().map(|&t| t.0).collect();
    let b_targets: Vec<Target> = b.iter().map(|&t| t.0).collect();

    list_lte_circuit(builder, a_targets, b_targets, 32)
}
