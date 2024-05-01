use std::{fs, path::PathBuf};

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};
use city_mono::{
    btc::{
        data::rollup::introspection::BlockSpendIntrospectionHint,
        gadgets::rollup::introspection::BTCRollupIntrospectionGadget,
    },
    common::hash::accelerator::sha256::{
        planner::{Sha256AcceleratorDomainPlanner, SmartSha256AcceleratorGadgetWithDomain},
        smartgadget::Sha256AirParametersStandard,
    },
};
use starkyx::machine::hash::sha::sha256::SHA256;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!(
        "{}/examples/simple_rollup_spend_hints_0.json",
        root.display()
    );
    let file_data = fs::read(path).unwrap();
    let introspection_hints: Vec<BlockSpendIntrospectionHint> =
        serde_json::from_slice(&file_data).unwrap();

    run_simple_rollup_3(&introspection_hints[0])
}
fn run_simple_rollup_3(introspection_hint: &BlockSpendIntrospectionHint) {
    // build circuit once

    let hint_result = introspection_hint.get_introspection_result::<PoseidonHash, F>();
    let hint_finalized_result = hint_result.get_finalized_result::<PoseidonHash>();
    let final_hash_hint = hint_finalized_result.get_combined_hash::<PoseidonHash>();
    let sighash_felt252 = hint_result.sighash_felt252;
    println!("[expected] final hash hint: {:?}", final_hash_hint.0);
    println!("[expected] sighash_felt256: {:?}", sighash_felt252.0);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut dp = Sha256AcceleratorDomainPlanner::new();

    let mut introspection_gadget = BTCRollupIntrospectionGadget::add_virtual_to(
        &mut builder,
        &introspection_hint.get_config(),
    );

    let introspection_result = introspection_gadget.generate_result(&mut builder);
    let introspection_finalized =
        introspection_result.get_finalized_result::<PoseidonHash, _, D>(&mut builder);
    let introspection_finalized_hash =
        introspection_finalized.get_combined_hash::<PoseidonHash, _, D>(&mut builder);

    builder.register_public_inputs(&introspection_finalized_hash.elements);
    builder.register_public_inputs(&introspection_result.sighash_felt252.elements);

    introspection_gadget.finalize(&mut builder, &mut dp);

    println!("domain_planner: {}", dp.domains[0].derived_hash_ids.len());
    println!("domain_planner: {}", dp.domains[0].planned_hashes.len());

    let mut finalizer = SmartSha256AcceleratorGadgetWithDomain::<
        SHA256,
        Sha256AirParametersStandard<F>,
        C,
        D,
        64,
    >::new(&mut builder, dp);

    let num_gates = builder.num_gates();
    // let copy_constraints = builder.copy_constraints.len();

    let targets_to_constants = builder.get_targets_to_constants_map();
    let data = builder.build::<C>();
    println!(
        "circuit num_gates={}, quotient_degree_factor={}",
        num_gates, data.common.quotient_degree_factor
    );

    let mut pw = PartialWitness::new();

    introspection_gadget.set_witness::<_, F, D, _>(&mut pw, &mut finalizer, introspection_hint);

    finalizer.finalize_witness(&mut pw, &targets_to_constants);

    let start_time = std::time::Instant::now();
    let proof = data.prove(pw).unwrap();
    let duration_ms = start_time.elapsed().as_millis();
    println!("proved in {}ms", duration_ms);
    println!("public_inputs: {:?}", proof.public_inputs);

    assert!(data.verify(proof).is_ok());
}
