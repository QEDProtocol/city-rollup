use city_common_circuit::u32::gates::comparison::ComparisonGate;
use plonky2::{
    field::extension::Extendable,
    gates::{constant::ConstantGate, gate::GateRef},
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

pub fn add_common_op_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) {
    builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(
        builder.config.num_constants,
    )));
    builder.add_gate_to_gate_set(GateRef::new(ComparisonGate::new(32, 16)));
}
