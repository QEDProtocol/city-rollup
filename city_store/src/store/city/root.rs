use city_crypto::hash::traits::hasher::{MerkleHasher, PoseidonHasher};
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
}
