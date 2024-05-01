use std::marker::PhantomData;

use city_crypto::hash::merkle::core::DeltaMerkleProofCore;
use city_crypto::hash::merkle::core::MerkleProofCore;
use city_crypto::hash::traits::hasher::MerkleZeroHasherWithMarkedLeaf;
use kvq::traits::KVQBinaryStore;
use kvq::traits::KVQPair;
use kvq::traits::KVQSerializable;
use kvq::traits::KVQStoreAdapter;
use serde::Deserialize;
use serde::Serialize;

use super::key::KVQMerkleNodeKey;
const CHECKPOINT_SIZE: usize = 8;
pub trait KVQMerkleTreeModelCore<
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S: KVQBinaryStore,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>
{
    fn get_node_exact(store: &S, key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<Hash> {
        KVA::get_exact(store, key)
    }
    fn get_nodes_exact_vec(
        store: &S,
        keys: &[KVQMerkleNodeKey<TABLE_TYPE>],
    ) -> anyhow::Result<Vec<Hash>> {
        KVA::get_many_exact(store, keys)
    }
    fn get_node_optional(
        store: &S,
        key: &KVQMerkleNodeKey<TABLE_TYPE>,
    ) -> anyhow::Result<Option<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>>> {
        KVA::get_leq_kv(store, key, CHECKPOINT_SIZE)
    }
    fn get_node(
        store: &S,
        tree_height: usize,
        key: &KVQMerkleNodeKey<TABLE_TYPE>,
    ) -> anyhow::Result<Hash> {
        match KVA::get_leq(store, key, CHECKPOINT_SIZE)? {
            Some(v) => Ok(v),
            None => {
                if MARK_LEAVES {
                    return Ok(Hasher::get_zero_hash_marked(
                        tree_height - (key.level as usize),
                    ));
                } else {
                    Ok(Hasher::get_zero_hash(tree_height - (key.level as usize)))
                }
            }
        }
    }
    fn get_nodes(
        store: &S,
        tree_height: usize,
        keys: &[KVQMerkleNodeKey<TABLE_TYPE>],
    ) -> anyhow::Result<Vec<Hash>> {
        let result = KVA::get_many_leq(store, keys, CHECKPOINT_SIZE)?;
        Ok(result
            .iter()
            .enumerate()
            .map(|(i, v)| match v {
                Some(v) => *v,
                None => Hasher::get_zero_hash(tree_height - (keys[i].level as usize)),
            })
            .collect())
    }
    fn set_node_kv(
        store: &mut S,
        kv: &KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    ) -> anyhow::Result<()> {
        KVA::set_ref(store, &kv.key, &kv.value)
    }
    fn set_node(
        store: &mut S,
        key: &KVQMerkleNodeKey<TABLE_TYPE>,
        value: &Hash,
    ) -> anyhow::Result<()> {
        KVA::set_ref(store, key, value)
    }
    fn set_nodes_ref<'a>(
        store: &mut S,
        nodes: &[KVQPair<&'a KVQMerkleNodeKey<TABLE_TYPE>, &'a Hash>],
    ) -> anyhow::Result<()> {
        KVA::set_many_ref(store, nodes)
    }
    fn set_nodes<'a>(
        store: &mut S,
        nodes: &[KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>],
    ) -> anyhow::Result<()> {
        KVA::set_many(store, nodes)
    }
    fn get_leaf(
        store: &S,
        key: &KVQMerkleNodeKey<TABLE_TYPE>,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        let nodes = Self::get_nodes(
            store,
            key.level as usize,
            &vec![vec![*key], key.siblings(), vec![key.root()]].concat(),
        )?;
        let value = nodes[0];
        let root_ind = nodes.len() - 1;
        let siblings = nodes[1..root_ind].to_vec();
        let root = nodes[root_ind];
        Ok(MerkleProofCore::<Hash> {
            root,
            value,
            siblings,
            index: key.index,
        })
    }

    fn set_leaf(
        store: &mut S,
        key: &KVQMerkleNodeKey<TABLE_TYPE>,
        value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        let old_proof = Self::get_leaf(store, key)?;
        let mut current_value = value;
        let mut current_key = *key;

        let mut updates: Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>> =
            Vec::with_capacity((key.level as usize) + 1);

        let height = key.level as usize;
        if height > 0 {
            let new_key = current_key.parent();
            let index = current_key.index;
            updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
                key: current_key,
                value: current_value,
            });
            current_value = if index & 1 == 0 {
                if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&current_value, &old_proof.siblings[0])
                } else {
                    Hasher::two_to_one(&current_value, &old_proof.siblings[0])
                }
            } else {
                if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&old_proof.siblings[0], &current_value)
                } else {
                    Hasher::two_to_one(&old_proof.siblings[0], &current_value)
                }
            };
            current_key = new_key;
        }
        for i in 1..height {
            let new_key = current_key.parent();
            let index = current_key.index;
            updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
                key: current_key,
                value: current_value,
            });
            current_value = if index & 1 == 0 {
                Hasher::two_to_one(&current_value, &old_proof.siblings[i])
            } else {
                Hasher::two_to_one(&old_proof.siblings[i], &current_value)
            };
            current_key = new_key;
        }
        updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
            key: current_key,
            value: current_value,
        });

        Self::set_nodes(store, &updates)?;
        Ok(DeltaMerkleProofCore::<Hash> {
            old_root: old_proof.root,
            old_value: old_proof.value,

            new_root: current_value,
            new_value: value,

            siblings: old_proof.siblings,
            index: key.index,
        })
    }
}
pub trait KVQFixedConfigMerkleTreeModelCore<
    const TREE_ID: u8,
    const TREE_HEIGHT: u8,
    const PRIMARY_ID: u64,
    const SECONDARY_ID: u32,
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S: KVQBinaryStore,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>: KVQMerkleTreeModelCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
    fn new_node_key_fc(checkpoint_id: u64, level: u8, index: u64) -> KVQMerkleNodeKey<TABLE_TYPE> {
        KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id: TREE_ID,
            primary_id: PRIMARY_ID,
            secondary_id: SECONDARY_ID,
            level,
            index,
            checkpoint_id,
        }
    }
    fn new_leaf_key_fc(checkpoint_id: u64, index: u64) -> KVQMerkleNodeKey<TABLE_TYPE> {
        KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id: TREE_ID,
            primary_id: PRIMARY_ID,
            secondary_id: SECONDARY_ID,
            level: TREE_HEIGHT,
            index,
            checkpoint_id,
        }
    }
    fn set_leaf_fc(
        store: &mut S,
        checkpoint_id: u64,
        index: u64,
        value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::set_leaf(store, &Self::new_leaf_key_fc(checkpoint_id, index), value)
    }
    fn get_leaf_fc(
        store: &S,
        checkpoint_id: u64,
        index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        Self::get_leaf(store, &Self::new_leaf_key_fc(checkpoint_id, index))
    }
    fn get_leaf_value_fc(store: &mut S, checkpoint_id: u64, index: u64) -> anyhow::Result<Hash> {
        Self::get_node(
            store,
            TREE_HEIGHT as usize,
            &Self::new_leaf_key_fc(checkpoint_id, index),
        )
    }
    fn get_node_value_fc(
        store: &mut S,
        checkpoint_id: u64,
        level: u8,
        index: u64,
    ) -> anyhow::Result<Hash> {
        Self::get_node(
            store,
            TREE_HEIGHT as usize,
            &Self::new_node_key_fc(checkpoint_id, level, index),
        )
    }
    fn get_root_fc(store: &mut S, checkpoint_id: u64) -> anyhow::Result<Hash> {
        Self::get_node(
            store,
            TREE_HEIGHT as usize,
            &Self::new_node_key_fc(checkpoint_id, 0, 0),
        )
    }
}

pub struct KVQMerkleTreeModel<
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S: KVQBinaryStore,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
> {
    _hasher: PhantomData<Hasher>,
    _hash: PhantomData<Hash>,
    _s: PhantomData<S>,
    _kva: PhantomData<KVA>,
}
impl<
        const TABLE_TYPE: u16,
        const MARK_LEAVES: bool,
        S: KVQBinaryStore,
        Hash: PartialEq + KVQSerializable + Copy,
        Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
        KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    > KVQMerkleTreeModelCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
    for KVQMerkleTreeModel<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
}

pub struct KVQFixedConfigMerkleTreeModel<
    const TREE_ID: u8,
    const TREE_HEIGHT: u8,
    const PRIMARY_ID: u64,
    const SECONDARY_ID: u32,
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S: KVQBinaryStore,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
> {
    _hasher: PhantomData<Hasher>,
    _hash: PhantomData<Hash>,
    _s: PhantomData<S>,
    _kva: PhantomData<KVA>,
}

impl<
        const TREE_ID: u8,
        const TREE_HEIGHT: u8,
        const PRIMARY_ID: u64,
        const SECONDARY_ID: u32,
        const TABLE_TYPE: u16,
        const MARK_LEAVES: bool,
        S: KVQBinaryStore,
        KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
        Hash: Copy + PartialEq + KVQSerializable,
        Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
    > KVQMerkleTreeModelCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
    for KVQFixedConfigMerkleTreeModel<
        TREE_ID,
        TREE_HEIGHT,
        PRIMARY_ID,
        SECONDARY_ID,
        TABLE_TYPE,
        MARK_LEAVES,
        S,
        KVA,
        Hash,
        Hasher,
    >
{
}
impl<
        const TREE_ID: u8,
        const TREE_HEIGHT: u8,
        const PRIMARY_ID: u64,
        const SECONDARY_ID: u32,
        const TABLE_TYPE: u16,
        const MARK_LEAVES: bool,
        S: KVQBinaryStore,
        KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
        Hash: Copy + PartialEq + KVQSerializable,
        Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
    >
    KVQFixedConfigMerkleTreeModelCore<
        TREE_ID,
        TREE_HEIGHT,
        PRIMARY_ID,
        SECONDARY_ID,
        TABLE_TYPE,
        MARK_LEAVES,
        S,
        KVA,
        Hash,
        Hasher,
    >
    for KVQFixedConfigMerkleTreeModel<
        TREE_ID,
        TREE_HEIGHT,
        PRIMARY_ID,
        SECONDARY_ID,
        TABLE_TYPE,
        MARK_LEAVES,
        S,
        KVA,
        Hash,
        Hasher,
    >
{
}
