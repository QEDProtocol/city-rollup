use city_rollup_common::api::data::block::requested_actions::CityAddDepositRequest;
use kvq::traits::KVQBinaryStore;

use crate::config::CityDeltaMerkleProof;

use super::base::CityStore;

impl<S: KVQBinaryStore> CityStore<S> {
    pub fn process_add_deposit_request(
        store: &mut S,
        checkpoint_id: u64,
        deposit_id: u64,
        req: &CityAddDepositRequest,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        Self::add_deposit_from_request(store, checkpoint_id, deposit_id, req)
    }
}
