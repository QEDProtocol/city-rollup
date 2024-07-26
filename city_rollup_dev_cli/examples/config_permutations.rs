use std::sync::Arc;

use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::sighash_circuits::{sighash::CRSigHashCircuit, sighash_refund::CRSigHashRefundCircuit};
use city_rollup_common::introspection::rollup::introspection::{BlockSpendCoreConfig, RefundIntrospectionGadgetConfig};
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use indicatif::{ProgressBar, ProgressStyle};

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
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let mt = SigHashMerkleTree::new();
    println!("root: {:?}", mt.root.0);
    let max_deposits = 4;
    let max_widthdrawals = 4;
    let block_spend_config = BlockSpendCoreConfig::standard_p2sh_p2pkh();
    let permutations = block_spend_config
        .generate_permutations(max_deposits, max_widthdrawals);
    let style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}").unwrap()
        .progress_chars("##-");

    let pb = ProgressBar::new(permutations.len() as u64);
    pb.set_style(style.clone());
    let pb = Arc::new(pb);

    let mut fingerprints: Vec<QHashOut<F>> = vec![QHashOut::default(); permutations.len() + 1];
    let config = RefundIntrospectionGadgetConfig::generate_from_template(&block_spend_config);
    let circuit = CRSigHashRefundCircuit::<C, D>::new(config);
    let fingerprint = circuit.get_fingerprint();
    fingerprints[0] = fingerprint;

    parallelize(&mut fingerprints[1..], |fingerprints, start| {
        for (i, fingerprint) in fingerprints.iter_mut().enumerate() {
            let idx = start + i;
            let circuit = CRSigHashCircuit::<C, D>::new(permutations[idx].clone());
            *fingerprint = circuit.get_fingerprint();
            pb.inc(1);
        }
    });

    for (i, fingerprint) in fingerprints.iter().enumerate() {
        println!("[{}]: {:?}", i, fingerprint);
    }

    pb.finish();
}
