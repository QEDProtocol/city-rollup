use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub trait PMCircuitCustomizer<F: RichField + Extendable<D>, const D: usize> {
    fn augment_circuit(&self, builder: &mut CircuitBuilder<F, D>);
}
