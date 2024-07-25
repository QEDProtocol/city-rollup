use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::sighash_circuits::{sighash::CRSigHashCircuit, sighash_refund::CRSigHashRefundCircuit};
use city_rollup_common::introspection::rollup::introspection::{BlockSpendCoreConfig, RefundIntrospectionGadgetConfig};
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

// TODOL cannot use rayon, plonky2 crashes
pub fn parallelize<T: Send, F: Fn(&mut [T], usize) + Send + Sync + Clone>(v: &mut [T], f: F) {
    let n = v.len();
    let num_threads = rayon::current_num_threads();
    let mut chunk = (n as usize) / num_threads;
    if chunk < num_threads {
        chunk = 1;
    }

    rayon::scope(|scope| {
        for (chunk_num, v) in v.chunks_mut(chunk).enumerate() {
            let f = f.clone();
            scope.spawn(move |_| {
                let start = chunk_num * chunk;
                f(v, start);
            });
        }
    });
}

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
    println!(
        "permutations: {:?}",
        serde_json::to_string(&permutations).unwrap()
    );
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
        println!("[{}]: {:?}", i+1, fingerprint);
        fingerprints.push(fingerprint);
        timer.event(format!("generated fingerprint {}", i+1));
    }

    println!(
        "permutations: {:?}",
        serde_json::to_string(&fingerprints).unwrap()
    );
}
