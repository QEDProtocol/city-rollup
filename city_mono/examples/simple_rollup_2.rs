use std::{fs, path::PathBuf};

use plonky2::{
    field::goldilocks_field::GoldilocksField,
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
    cityrollup::data::btc_spend_info::SimpleRollupBTCSpendInfo,
    common::hash::accelerator::sha256::{
        planner::{Sha256AcceleratorDomainPlanner, SmartSha256AcceleratorGadgetWithDomain},
        smartgadget::Sha256AirParametersStandard,
    },
};
use starkyx::machine::hash::sha::sha256::SHA256;

fn run_simple_rollup_old(introspection_hint: &BlockSpendIntrospectionHint) {
    // build circuit once

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

    introspection_gadget.finalize(&mut builder, &mut dp);

    println!("domain_planner: {}", dp.domains[0].derived_hash_ids.len());
    println!("domain_planner: {}", dp.domains[0].planned_hashes.len());

    builder.register_public_inputs(&introspection_gadget.current_sighash);

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

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!(
        "{}/examples/simple_rollup_spend_info_0.json",
        root.display()
    );
    let file_data = fs::read(path).unwrap();
    let input: SimpleRollupBTCSpendInfo = serde_json::from_slice(&file_data).unwrap();

    let introspection_hints = input.to_block_spend_hints().unwrap();

    println!(
        "introspection_hints: {}",
        serde_json::to_string(&introspection_hints).unwrap()
    );

    run_simple_rollup_old(&introspection_hints[0])
}
