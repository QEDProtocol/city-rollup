use city_common::math::ceil_div_usize;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, CommonCircuitData},
        config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};


// See: plonky2/plonky2/src/recursion/
pub fn dummy_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    nonzero_public_inputs: HashMap<usize, F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
where
{
    let mut pw = PartialWitness::new();
    for i in 0..circuit.common.num_public_inputs {
        let pi = nonzero_public_inputs.get(&i).copied().unwrap_or_default();
        pw.set_target(circuit.prover_only.public_inputs[i], pi);
    }
    circuit.prove(pw)
}

/// Generate a circuit matching a given `CommonCircuitData`.
pub fn dummy_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    common_data: &CommonCircuitData<F, D>,
) -> CircuitData<F, C, D> {
    let config = common_data.config.clone();
    assert!(
        !common_data.config.zero_knowledge,
        "Degree calculation can be off if zero-knowledge is on."
    );

    // Number of `NoopGate`s to add to get a circuit of size `degree` in the end.
    // Need to account for public input hashing, a `PublicInputGate` and a `ConstantGate`.
    let degree = common_data.degree();
    let num_noop_gate = degree - ceil_div_usize(common_data.num_public_inputs, 8) - 2;

    let mut builder = CircuitBuilder::<F, D>::new(config);
    for _ in 0..num_noop_gate {
        builder.add_gate(NoopGate, vec![]);
    }
    for gate in &common_data.gates {
        builder.add_gate_to_gate_set(gate.clone());
    }
    for _ in 0..common_data.num_public_inputs {
        builder.add_virtual_public_input();
    }

    let circuit = builder.build::<C>();
    assert_eq!(&circuit.common, common_data);
    circuit
}
