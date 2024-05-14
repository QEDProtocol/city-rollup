use std::{fs, path::PathBuf};

use city_rollup_common::api::data::btc_spend_info::SimpleRollupBTCSpendInfo;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!(
        "{}/examples/covenant_js_output_example_3.json",
        root.display()
    );
    let file_data = fs::read(path).unwrap();
    let simple_spend_info: SimpleRollupBTCSpendInfo = serde_json::from_slice(&file_data).unwrap();

    let introspection_hints = simple_spend_info.to_block_spend_hints().unwrap();
    let configs = introspection_hints
        .iter()
        .map(|x| x.get_config())
        .collect::<Vec<_>>();
    println!("configs: {}", serde_json::to_string(&configs).unwrap());
}
