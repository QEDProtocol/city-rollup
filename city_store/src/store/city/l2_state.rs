use city_rollup_common::api::data::store::CityL2BlockState;
use kvq::traits::{KVQBinaryStore, KVQBinaryStoreReader};

use crate::{
    config::L2BlockStateStore,
    models::l2_block_state::model::{L2BlockStatesModelCore, L2BlockStatesModelReaderCore},
};

use super::base::CityStore;

impl<S: KVQBinaryStoreReader> CityStore<S> {
    pub fn get_block_state(store: &S, checkpoint_id: u64) -> anyhow::Result<CityL2BlockState> {
        L2BlockStateStore::get_block_state_by_id(store, checkpoint_id)
    }
}

impl<S: KVQBinaryStore> CityStore<S> {
    pub fn set_block_state(store: &mut S, block_state: &CityL2BlockState) -> anyhow::Result<()> {
        L2BlockStateStore::set_block_state_ref(store, block_state)?;
        Ok(())
    }
}
