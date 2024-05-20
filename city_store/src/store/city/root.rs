use city_crypto::hash::{
    base_types::{
        felt252::{felt252_hashout_to_hash256_le, hashout_to_felt252_hashout},
        hash160::Hash160,
    },
    traits::hasher::{MerkleHasher, PoseidonHasher},
};
use city_rollup_common::block_template::{
    get_block_script_bytes, get_block_script_hash, BLOCK_SCRIPT_LENGTH,
};
use kvq::traits::KVQBinaryStoreReader;

use crate::config::CityHash;

use super::base::CityStore;

impl<S: KVQBinaryStoreReader> CityStore<S> {
    pub fn get_city_root(store: &S, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        let user_root = Self::get_user_tree_root(store, checkpoint_id)?;
        let withdrawal_root = Self::get_withdrawal_tree_root(store, checkpoint_id)?;
        let deposit_root = Self::get_deposit_tree_root(store, checkpoint_id)?;

        let pt1 = PoseidonHasher::two_to_one(&user_root, &withdrawal_root);
        let pt2 = PoseidonHasher::two_to_one(&pt1, &deposit_root);
        Ok(pt2)
    }
    pub fn get_city_block_script(
        store: &S,
        checkpoint_id: u64,
    ) -> anyhow::Result<[u8; BLOCK_SCRIPT_LENGTH]> {
        let start_root_state_hash = Self::get_city_root(
            store,
            if checkpoint_id == 0 {
                0
            } else {
                checkpoint_id - 1
            },
        )?;
        /*
        println!(
            "start_root_state_hash[{}]: {:?}",
            checkpoint_id, start_root_state_hash.0
        );*/
        let root_state_hash_bytes =
            felt252_hashout_to_hash256_le(hashout_to_felt252_hashout(start_root_state_hash.0)).0;

        Ok(get_block_script_bytes(
            root_state_hash_bytes,
            checkpoint_id < 2,
        ))
    }
    pub fn get_city_block_deposit_address(
        store: &S,
        checkpoint_id: u64,
    ) -> anyhow::Result<Hash160> {
        let start_root_state_hash = Self::get_city_root(
            store,
            if checkpoint_id == 0 {
                0
            } else {
                checkpoint_id - 1
            },
        )?;
        let root_state_hash_bytes =
            felt252_hashout_to_hash256_le(hashout_to_felt252_hashout(start_root_state_hash.0)).0;

        Ok(get_block_script_hash(
            root_state_hash_bytes,
            checkpoint_id < 2,
        ))
    }
    pub fn get_city_block_deposit_address_string(
        store: &S,
        checkpoint_id: u64,
    ) -> anyhow::Result<String> {
        Ok(Self::get_city_block_deposit_address(store, checkpoint_id)?.to_p2sh_address())
    }
}
