use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::sighash_circuits::{sighash::CRSigHashCircuit, sighash_refund::CRSigHashRefundCircuit};
use city_rollup_common::introspection::rollup::introspection::{BlockSpendCoreConfig, RefundIntrospectionGadgetConfig};
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

fn main() {
    let mt = SigHashMerkleTree::new();
    println!("root: {:?}", mt.root.0);
    let max_deposits = 4;
    let max_widthdrawals = 4;
    let mut timer = TraceTimer::new("config_permutations");
    timer.lap("start");
    let block_spend_config = BlockSpendCoreConfig::standard_p2sh_p2pkh();
    let permutations = block_spend_config
        .generate_permutations(max_deposits, max_widthdrawals);
    let id_permutations = block_spend_config
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
    let config = RefundIntrospectionGadgetConfig::generate_from_template(&block_spend_config);
    let circuit = CRSigHashRefundCircuit::<C, D>::new(config);
    let fingerprint = circuit.get_fingerprint();
    fingerprints.push(fingerprint);
    println!("[{}]: {:?}", 0, fingerprint);

    for i in 0..permutations.len() {
        let circuit = CRSigHashCircuit::<C, D>::new(permutations[i].clone());
        let fingerprint = circuit.get_fingerprint();
        println!("[{}]: {:?}", i, fingerprint);
        fingerprints.push(fingerprint);
        timer.event(format!("generated fingerprint {}", i));
    println!(
        "permutations: {}",
        serde_json::to_string(&fingerprints).unwrap()
    );
    }

    println!("Total permutations: {}", permutations.len());
    println!(
        "permutations: {}",
        serde_json::to_string(&fingerprints).unwrap()
    );
}
