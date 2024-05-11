use city_rollup_common::api::data::block::requested_actions::CityAddWithdrawalRequest;
use city_rollup_common::api::data::store::CityL1Withdrawal;
use kvq::traits::KVQBinaryStore;
use kvq::traits::KVQBinaryStoreReader;

use super::base::CityStore;
use crate::config::CityDeltaMerkleProof;
use crate::config::CityHash;
use crate::config::CityMerkleProof;
use crate::config::L1WithdrawalTreeStore;
use crate::models::kvq_merkle::model::KVQFixedConfigMerkleTreeModelCore;
use crate::models::kvq_merkle::model::KVQFixedConfigMerkleTreeModelReaderCore;

impl<S: KVQBinaryStoreReader> CityStore<S> {
    pub fn get_withdrawal_tree_root(store: &S, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        L1WithdrawalTreeStore::<S>::get_root_fc(store, checkpoint_id)
    }
    pub fn get_withdrawal_by_id(
        store: &S,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal> {
        let leaf = L1WithdrawalTreeStore::get_leaf_value_fc(store, checkpoint_id, withdrawal_id)?;
        Ok(CityL1Withdrawal::from_hash(withdrawal_id, leaf))
    }
    pub fn get_withdrawals_by_id(
        store: &S,
        checkpoint_id: u64,
        withdrawal_ids: &[u64],
    ) -> anyhow::Result<Vec<CityL1Withdrawal>> {
        let leaves =
            L1WithdrawalTreeStore::get_leaf_values_fc(store, checkpoint_id, withdrawal_ids)?;
        Ok(leaves
            .iter()
            .zip(withdrawal_ids)
            .map(|(leaf, withdrawal_id)| CityL1Withdrawal::from_hash(*withdrawal_id, *leaf))
            .collect::<Vec<_>>())
    }
    pub fn get_withdrawal_hash(
        store: &S,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityHash> {
        L1WithdrawalTreeStore::get_leaf_value_fc(store, checkpoint_id, withdrawal_id)
    }
    pub fn get_withdrawal_leaf_merkle_proof(
        store: &S,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        L1WithdrawalTreeStore::get_leaf_fc(store, checkpoint_id, withdrawal_id)
    }
}

impl<S: KVQBinaryStore> CityStore<S> {
    pub fn set_withdrawal(
        store: &mut S,
        checkpoint_id: u64,
        withdrawal: &CityL1Withdrawal,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        let withdrawal_hash: CityHash = withdrawal.into();

        L1WithdrawalTreeStore::set_leaf_fc(
            store,
            checkpoint_id,
            withdrawal.withdrawal_id,
            withdrawal_hash,
        )
    }
    pub fn add_withdrawal_to_tree_from_request(
        store: &mut S,
        checkpoint_id: u64,
        req: &CityAddWithdrawalRequest,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        let withdrawal = CityL1Withdrawal {
            withdrawal_id: req.withdrawal_id,
            address: req.destination,
            address_type: req.destination_type,
            value: req.value,
        };
        Self::set_withdrawal(store, checkpoint_id, &withdrawal)
    }
    pub fn mark_withdrawal_as_completed(
        store: &mut S,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        L1WithdrawalTreeStore::set_leaf_fc(store, checkpoint_id, withdrawal_id, CityHash::ZERO)
    }
}
