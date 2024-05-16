use std::{fs, path::PathBuf};

use city_crypto::hash::qhashout::QHashOut;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{RichField},
};
fn get_constant_hash_string<F: RichField>(hash: QHashOut<F>, suffix: &str) -> String {
    format!(
        "QHashOut(HashOut{{elements: [GoldilocksField({}), GoldilocksField({}), GoldilocksField({}), GoldilocksField({})]}}){}",
        hash.0.elements[0], hash.0.elements[1], hash.0.elements[2], hash.0.elements[3], suffix
    )
}
fn get_constant_hashes_string<F: RichField>(hashes: &[QHashOut<F>]) -> String {
    let mut result = String::new();
    for (_, hash) in hashes.iter().enumerate() {
        result.push_str(&get_constant_hash_string(hash.clone(), ",\n"));
    }
    result
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!("{}/examples/config_permutations_4x4.json", root.display());
    let file_data = fs::read(path).unwrap();
    let hashes: Vec<QHashOut<GoldilocksField>> = serde_json::from_slice(&file_data).unwrap();
    println!("[\n{}\n]", get_constant_hashes_string(&hashes));
}
