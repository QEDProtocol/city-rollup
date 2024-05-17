use plonky2::{
    field::extension::Extendable,
    gates::{
        arithmetic_base::ArithmeticGate, arithmetic_extension::ArithmeticExtensionGate,
        base_sum::BaseSumGate, constant::ConstantGate, gate::GateRef,
        multiplication_extension::MulExtensionGate, noop::NoopGate, poseidon::PoseidonGate,
        poseidon_mds::PoseidonMdsGate, random_access::RandomAccessGate, reducing::ReducingGate,
        reducing_extension::ReducingExtensionGate,
    },
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::u32::gates::comparison::ComparisonGate;

pub fn pad_circuit_degree<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target_degree: usize,
) {
    while builder.num_gates() < (1u64 << (target_degree as u64)) as usize {
        builder.add_gate(NoopGate, vec![]);
    }
}
pub trait CircuitBuilderCityCommonGates<F: RichField + Extendable<D>, const D: usize> {
    fn add_city_common_gates(&mut self, coset_gate: Option<GateRef<F, D>>);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCityCommonGates<F, D>
    for CircuitBuilder<F, D>
{
    fn add_city_common_gates(&mut self, coset_gate: Option<GateRef<F, D>>) {
        self.add_gate_to_gate_set(GateRef::new(ConstantGate::new(self.config.num_constants)));
        self.add_gate_to_gate_set(GateRef::new(ComparisonGate::new(32, 16)));
        self.add_gate_to_gate_set(GateRef::new(RandomAccessGate::new_from_config(
            &self.config,
            4,
        )));
        self.add_gate_to_gate_set(GateRef::new(PoseidonGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(PoseidonMdsGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(ReducingGate::<D>::new(43)));
        self.add_gate_to_gate_set(GateRef::new(ReducingExtensionGate::<D>::new(32)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticExtensionGate::new_from_config(
            &self.config,
        )));
        self.add_gate_to_gate_set(GateRef::new(MulExtensionGate::new_from_config(
            &self.config,
        )));
        self.add_gate_to_gate_set(GateRef::new(BaseSumGate::<2>::new_from_config::<F>(
            &self.config,
        )));
        if coset_gate.is_some() {
            self.add_gate_to_gate_set(coset_gate.unwrap());
        }
    }
}
