use plonky2::field::extension::Extendable;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub fn pad_circuit_degree<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target_degree: usize,
) {
    while builder.num_gates() < (1u64 << (target_degree as u64)) as usize {
        builder.add_gate(NoopGate, vec![]);
    }
}
