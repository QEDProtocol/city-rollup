use city_crypto::hash::{merkle::core::MerkleProofCore, qhashout::QHashOut};
use city_rollup_common::{
    config::sighash_wrapper_config::{
        SIGHASH_CIRCUIT_FINGERPRINTS, SIGHASH_CIRCUIT_MAX_DEPOSITS,
        SIGHASH_CIRCUIT_MAX_WITHDRAWALS, SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT,
    },
    introspection::rollup::introspection::{
        BlockSpendCoreConfig, SigHashGadgetId, SigHashGadgetIdWithIndex,
    },
};
use kvq::{adapters::standard::KVQStandardAdapter, memory::simple::KVQSimpleMemoryBackingStore};

use crate::{
    config::{CityHash, CityHasher, F},
    models::kvq_merkle::{
        key::KVQMerkleNodeKey,
        model::{
            KVQFixedConfigMerkleTreeModel, KVQFixedConfigMerkleTreeModelCore,
            KVQFixedConfigMerkleTreeModelReaderCore,
        },
    },
};

pub struct SigHashMerkleTree {
    pub store: KVQSimpleMemoryBackingStore,
    pub sorted_ids: Vec<SigHashGadgetId>,
    pub tree_height: usize,
    pub max_deposits: usize,
    pub max_withdrawals: usize,
    pub root: QHashOut<F>,
}
type SigHashTreeStore = KVQFixedConfigMerkleTreeModel<
    1,
    SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT,
    1,
    1,
    1,
    false,
    KVQSimpleMemoryBackingStore,
    KVQStandardAdapter<KVQSimpleMemoryBackingStore, KVQMerkleNodeKey<1>, CityHash>,
    CityHash,
    CityHasher,
>;
impl SigHashMerkleTree {
    pub fn new() -> Self {
        let tree_height = SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT as usize;
        let max_deposits = SIGHASH_CIRCUIT_MAX_DEPOSITS;
        let max_withdrawals = SIGHASH_CIRCUIT_MAX_WITHDRAWALS;
        let mut store = KVQSimpleMemoryBackingStore::new();
        let mut sorted_ids_with_index = BlockSpendCoreConfig::standard_p2sh_p2pkh()
            .generate_id_permutations(max_deposits, max_withdrawals)
            .into_iter()
            .enumerate()
            .map(|(i, x)| SigHashGadgetIdWithIndex {
                gadget_id: x,
                index: i + 1,
            })
            .collect::<Vec<_>>();
        sorted_ids_with_index.sort_by(|a, b| a.gadget_id.cmp(&b.gadget_id));
        SigHashTreeStore::set_leaf_fc(
                &mut store,
                0,
                0,
                SIGHASH_CIRCUIT_FINGERPRINTS[0],
        )
        .unwrap();
        sorted_ids_with_index.iter().enumerate().for_each(|(_, x)| {
            SigHashTreeStore::set_leaf_fc(
                &mut store,
                0,
                x.index as u64,
                SIGHASH_CIRCUIT_FINGERPRINTS[x.index],
            )
            .unwrap();
        });
        let sorted_ids = sorted_ids_with_index
            .into_iter()
            .map(|x| x.gadget_id)
            .collect::<Vec<_>>();
        let root = SigHashTreeStore::get_root_fc(&store, 0).unwrap();

        Self {
            store,
            sorted_ids,
            tree_height,
            max_deposits,
            max_withdrawals,
            root,
        }
    }
    pub fn get_proof_for_index(&self, index: u64) -> anyhow::Result<MerkleProofCore<CityHash>> {
        SigHashTreeStore::get_leaf_fc(&self.store, 0, index)
    }
    pub fn get_proof_for_id_ref(
        &self,
        id: &SigHashGadgetId,
    ) -> anyhow::Result<MerkleProofCore<CityHash>> {
        let index = self
            .sorted_ids
            .binary_search(id)
            .map_err(|_| anyhow::format_err!("unsupported sig hash config {:?}", id))?;
        SigHashTreeStore::get_leaf_fc(&self.store, 0, (index + 1) as u64)
    }
    pub fn get_proof_for_id(
        &self,
        id: SigHashGadgetId,
    ) -> anyhow::Result<MerkleProofCore<CityHash>> {
        self.get_proof_for_id_ref(&id)
    }
}
