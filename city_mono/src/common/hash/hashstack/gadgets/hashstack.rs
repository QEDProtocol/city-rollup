use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::common::QHashOut;

pub struct HashStackGadget {
    pub start_state: HashOutTarget,
    pub state: HashOutTarget,
    pub has_start_state_input: bool,
}

impl HashStackGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let start_state = builder.add_virtual_hash();
        Self {
            start_state: start_state,
            state: start_state,
            has_start_state_input: true,
        }
    }
    pub fn add_virtual_to_with_state(start_state: HashOutTarget) -> Self {
        Self {
            start_state: start_state,
            state: start_state,
            has_start_state_input: false,
        }
    }
    pub fn add_virtual_to_with_zero_start_state<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let zero = builder.zero();

        Self::add_virtual_to_with_state(HashOutTarget {
            elements: [zero, zero, zero, zero],
        })
    }
    pub fn push<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: HashOutTarget,
    ) {
        self.state =
            builder.hash_n_to_hash_no_pad::<H>([self.state.elements, value.elements].concat());
    }
    pub fn pop<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        new_state: HashOutTarget,
        value: HashOutTarget,
    ) {
        let computed_current_state =
            builder.hash_n_to_hash_no_pad::<H>([new_state.elements, value.elements].concat());
        builder.connect_hashes(self.state, computed_current_state);
        self.state = new_state;
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        start_state: HashOut<F>,
    ) {
        if self.has_start_state_input {
            witness.set_hash_target(self.start_state, start_state)
        }
    }
    pub fn set_witness_w<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        start_state: QHashOut<F>,
    ) {
        self.set_witness(witness, start_state.0)
    }
}
