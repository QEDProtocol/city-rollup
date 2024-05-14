use std::{fs, path::PathBuf};

use city_rollup_common::api::data::btc_spend_info::SimpleRollupBTCSpendInfo;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!("{}/examples/full_block_inputs.json", root.display());
    let file_data = fs::read(path).unwrap();
    let simple_spend_info: SimpleRollupBTCSpendInfo = serde_json::from_slice(&file_data).unwrap();

    let introspection_hints = simple_spend_info.to_block_spend_hints().unwrap();
    println!("{}", serde_json::to_string(&introspection_hints).unwrap());
}
