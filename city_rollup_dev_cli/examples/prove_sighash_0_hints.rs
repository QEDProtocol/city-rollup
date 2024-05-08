use std::fs;
use std::path::PathBuf;

use city_common::logging::debug_timer::DebugTimer;
use city_common_circuit::field::cubic::CubicExtendable;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::sighash_circuits::sighash::CRSigHashCircuit;
use city_rollup_common::introspection::rollup::introspection::BlockSpendIntrospectionGadgetConfig;
use city_rollup_common::introspection::rollup::introspection::BlockSpendIntrospectionHint;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

fn generate_circuit<C: GenericConfig<D> + 'static, const D: usize>(
    introspection_config: BlockSpendIntrospectionGadgetConfig,
) -> CRSigHashCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    CRSigHashCircuit::<C, D>::new(introspection_config)
}

fn prove_hint<C: GenericConfig<D> + 'static, const D: usize>(
    hint: &BlockSpendIntrospectionHint,
) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    let circuit = generate_circuit::<C, D>(hint.get_config());

    let proof = circuit.prove_base(hint)?;

    let result_finalized_hash = QHashOut::from_felt_slice(&proof.public_inputs[0..4]);
    let result_sighash_felt252 = QHashOut::from_felt_slice(&proof.public_inputs[4..8]);

    println!(
        "result_finalized_hash: {}",
        result_finalized_hash.to_string()
    );
    println!(
        "result_sighash_felt252: {}",
        result_sighash_felt252.to_string_le()
    );

    let expected_result = hint.get_introspection_result::<C::Hasher, C::F>();
    let expected_finalized_result = expected_result.get_finalized_result::<C::Hasher>();
    /*println!(
        "expected_trace_result:\n{}",
        serde_json::to_string_pretty(&expected_finalized_result).unwrap()
    );*/

    let expected_finalized_hash = expected_finalized_result.get_combined_hash::<C::Hasher>();
    let expected_sighash_felt252 = expected_result.sighash_felt252;
    let real_sighash = expected_result.sighash;

    println!(
        "expected_finalized_hash: {}",
        expected_finalized_hash.to_string()
    );
    println!(
        "expected_sighash_felt252: {}",
        expected_sighash_felt252.to_string_le()
    );
    println!("real_sighash: {}", real_sighash.to_string());
    /*
        for (i, d) in expected_result.deposits.iter().enumerate() {
            let preimage = vec![
                d.txid_224.0.elements.to_vec(),
                vec![d.value],
                d.public_key.to_vec(),
            ]
            .concat()
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<_>>();
            println!("deposit_{i}_preimage: {:?}", preimage);
            println!("deposit_{i}_hash: {}", d.get_hash::<C::Hasher>());
        }
    */
    Ok(proof)
}
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!("{}/examples/prove_sighash_0_hints.json", root.display());
    let file_data = fs::read(path).unwrap();
    let introspection_hints: Vec<BlockSpendIntrospectionHint> =
        serde_json::from_slice(&file_data).unwrap();

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let mut timer = DebugTimer::new("prove_sighash");
    timer.lap("start proving");
    let _proof = prove_hint::<C, D>(&introspection_hints[0]).unwrap();
    timer.lap("finished proving");

    //println!("Proof: {:?}", proof);
}
