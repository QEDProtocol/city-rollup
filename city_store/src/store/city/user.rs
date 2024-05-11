use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::api::data::store::CityUserState;
use kvq::traits::KVQBinaryStore;
use kvq::traits::KVQBinaryStoreReader;
use plonky2::field::types::Field;
use plonky2::field::types::Field64;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::HashOut;

use super::base::CityStore;
use crate::config::CityDeltaMerkleProof;
use crate::config::CityHash;
use crate::config::CityMerkleProof;
use crate::config::GlobalUserTreeStore;
use crate::config::F;
use crate::models::kvq_merkle::model::KVQFixedConfigMerkleTreeModelCore;
use crate::models::kvq_merkle::model::KVQFixedConfigMerkleTreeModelReaderCore;

impl<S: KVQBinaryStoreReader> CityStore<S> {
    pub fn get_user_tree_root(store: &S, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        GlobalUserTreeStore::<S>::get_root_fc(store, checkpoint_id)
    }
    pub fn get_user_by_id(
        store: &S,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityUserState> {
        let leaf_id = user_id * 2;
        let left = GlobalUserTreeStore::<S>::get_leaf_value_fc(store, checkpoint_id, leaf_id)?;
        let right = GlobalUserTreeStore::<S>::get_leaf_value_fc(store, checkpoint_id, leaf_id + 1)?;
        Ok(CityUserState::from_hash(user_id, left, right))
    }
    pub fn get_user_merkle_proof_by_id(
        store: &S,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        GlobalUserTreeStore::<S>::get_leaf_fc(store, checkpoint_id, user_id * 2)
    }
    pub fn get_user_tree_leaf(
        store: &S,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityHash> {
        GlobalUserTreeStore::<S>::get_leaf_value_fc(store, checkpoint_id, leaf_id)
    }
    pub fn get_user_tree_leaf_merkle_proof(
        store: &S,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        GlobalUserTreeStore::<S>::get_leaf_fc(store, checkpoint_id, leaf_id)
    }
}

impl<S: KVQBinaryStore> CityStore<S> {
    pub fn set_user_leaves(
        store: &mut S,
        checkpoint_id: u64,
        user: &CityUserState,
        left_before_right: bool,
    ) -> anyhow::Result<(CityDeltaMerkleProof, CityDeltaMerkleProof)> {
        let leaf_id = user.user_id * 2;
        let first_leaf = if left_before_right {
            user.get_left_leaf()
        } else {
            user.get_right_leaf()
        };
        let second_leaf = if left_before_right {
            user.get_left_leaf()
        } else {
            user.get_right_leaf()
        };

        let first_proof = GlobalUserTreeStore::set_leaf_fc(
            store,
            checkpoint_id,
            leaf_id + if left_before_right { 0 } else { 1 },
            first_leaf,
        )?;

        let second_proof = GlobalUserTreeStore::set_leaf_fc(
            store,
            checkpoint_id,
            leaf_id + if left_before_right { 1 } else { 0 },
            second_leaf,
        )?;
        Ok((first_proof, second_proof))
    }
    pub fn register_user(
        store: &mut S,
        checkpoint_id: u64,
        user_id: u64,
        public_key: CityHash,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        let leaf_id = user_id * 2;
        GlobalUserTreeStore::set_leaf_fc(store, checkpoint_id, leaf_id + 1, public_key)
    }
    pub fn decrement_user_balance(
        store: &mut S,
        checkpoint_id: u64,
        user_id: u64,
        amount: u64,
        nonce: Option<u64>,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        let leaf_id = user_id * 2;
        let current_leaf = GlobalUserTreeStore::get_leaf_value_fc(store, checkpoint_id, leaf_id)?;
        let current_balance = current_leaf.0.elements[0].to_canonical_u64();
        let current_nonce = current_leaf.0.elements[1].to_canonical_u64();
        if amount > current_balance {
            anyhow::bail!("Insufficient balance");
        }
        if nonce.is_some() {
            let nonce = nonce.unwrap();
            if nonce <= current_nonce {
                anyhow::bail!("Invalid nonce");
            } else if nonce > F::ORDER {
                anyhow::bail!("Nonce is too large");
            }
        }
        let new_balance = F::from_canonical_u64(current_balance - amount);
        let new_nonce = F::from_canonical_u64(nonce.unwrap_or(current_nonce));
        let new_user_leaf = QHashOut(HashOut {
            elements: [
                new_balance,
                new_nonce,
                current_leaf.0.elements[2],
                current_leaf.0.elements[3],
            ],
        });

        GlobalUserTreeStore::set_leaf_fc(store, checkpoint_id, leaf_id, new_user_leaf)
    }

    pub fn increment_user_balance(
        store: &mut S,
        checkpoint_id: u64,
        user_id: u64,
        amount: u64,
        nonce: Option<u64>,
    ) -> anyhow::Result<CityDeltaMerkleProof> {
        let leaf_id = user_id * 2;
        let current_leaf = GlobalUserTreeStore::get_leaf_value_fc(store, checkpoint_id, leaf_id)?;
        let current_balance = current_leaf.0.elements[0].to_canonical_u64();
        let current_nonce = current_leaf.0.elements[1].to_canonical_u64();

        let updated_balance = current_balance + amount;
        if updated_balance < current_balance || updated_balance > F::ORDER as u64 {
            anyhow::bail!("Balance overflow");
        }

        if nonce.is_some() {
            let nonce = nonce.unwrap();
            if nonce <= current_nonce {
                anyhow::bail!("Invalid nonce");
            } else if nonce > F::ORDER {
                anyhow::bail!("Nonce is too large");
            }
        }
        let new_balance = F::from_canonical_u64(updated_balance);
        let new_nonce = F::from_canonical_u64(nonce.unwrap_or(current_nonce));
        let new_user_leaf = QHashOut(HashOut {
            elements: [
                new_balance,
                new_nonce,
                current_leaf.0.elements[2],
                current_leaf.0.elements[3],
            ],
        });

        GlobalUserTreeStore::set_leaf_fc(store, checkpoint_id, leaf_id, new_user_leaf)
    }
}
