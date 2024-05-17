use city_crypto::hash::{
    base_types::hash160::Hash160,
    core::btc::{btc_hash160, btc_hash256},
};

use super::config::{GENESIS_BLOCK_SCRIPT_TEMPLATE, STANDARD_BLOCK_SCRIPT_TEMPLATE};

pub fn get_genesis_block_script_bytes(root_state_hash: [u8; 32]) -> [u8; 489] {
    let mut script = GENESIS_BLOCK_SCRIPT_TEMPLATE;
    script[1..33].copy_from_slice(&root_state_hash);
    script
}
pub fn get_standard_block_script_bytes(root_state_hash: [u8; 32]) -> [u8; 489] {
    let mut script = STANDARD_BLOCK_SCRIPT_TEMPLATE;
    script[1..33].copy_from_slice(&root_state_hash);
    script
}
pub fn get_block_script_bytes(root_state_hash: [u8; 32], is_genesis: bool) -> [u8; 489] {
    if is_genesis {
        get_genesis_block_script_bytes(root_state_hash)
    } else {
        get_standard_block_script_bytes(root_state_hash)
    }
}
pub fn get_block_script_hash(root_state_hash: [u8; 32], is_genesis: bool) -> Hash160 {
    let script = get_block_script_bytes(root_state_hash, is_genesis);
    btc_hash160(&script)
}
