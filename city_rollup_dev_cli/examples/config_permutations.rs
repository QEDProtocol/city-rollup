use city_common::logging::{trace_timer::TraceTimer};
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::sighash_circuits::sighash::CRSigHashCircuit;
use city_rollup_common::introspection::rollup::introspection::BlockSpendCoreConfig;
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

fn main() {
    let mt = SigHashMerkleTree::new();
    println!("root: {:?}", mt.root.0);
    let max_deposits = 1;
    let max_widthdrawals = 1;
    let mut timer = TraceTimer::new("config_permutations");
    timer.lap("start");
    let permutations = BlockSpendCoreConfig::standard_p2sh_p2pkh()
        .generate_permutations(max_deposits, max_widthdrawals);
    let id_permutations = BlockSpendCoreConfig::standard_p2sh_p2pkh()
        .generate_id_permutations(max_deposits, max_widthdrawals);
    println!(
        "id_permutations: {}",
        serde_json::to_string(&id_permutations).unwrap()
    );
    timer.event(format!("generated {} permutations", permutations.len()));
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let mut fingerprints: Vec<QHashOut<F>> = Vec::new();
    for i in 0..permutations.len() {
        let circuit = CRSigHashCircuit::<C, D>::new(permutations[i].clone());
        let fingerprint = circuit.get_fingerprint();
        println!("[{}]: {}", i, fingerprint.to_string());
        fingerprints.push(fingerprint);
        timer.event(format!("generated fingerprint {}", i));
    }
    println!("Total permutations: {}", permutations.len());
    println!(
        "permutations: {}",
        serde_json::to_string(&fingerprints).unwrap()
    );
}
