use std::collections::BTreeMap;

use crate::store::kvq::traits::{KVQBinaryStore, KVQPair};

pub struct KVQStagedStore<'a, S: KVQBinaryStore, B: KVQBinaryStore> {
    staged: S,
    backing: Box<&'a B>,
}
impl<'a, S: KVQBinaryStore, B: KVQBinaryStore> KVQStagedStore<'a, S, B> {
    pub fn new(staged: S, backing: Box<&'a B>) -> Self {
        Self { staged, backing }
    }
}

impl<'a, S: KVQBinaryStore, B: KVQBinaryStore> KVQBinaryStore for KVQStagedStore<'a, S, B> {
    fn get_exact(&self, key: &Vec<u8>) -> anyhow::Result<&Vec<u8>> {
        self.staged
            .get_exact(key)
            .or_else(|_| self.backing.get_exact(key))
    }

    fn get_many_exact(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<&Vec<u8>>> {
        let mut result = Vec::new();
        for key in keys {
            let r = self.get_exact(key)?;
            result.push(r);
        }
        Ok(result)
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        self.staged.set(key, value)
    }

    fn set_ptr(&mut self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()> {
        self.staged.set_ptr(key, value)
    }

    fn set_many_ref<'b>(
        &mut self,
        items: &[KVQPair<&'b Vec<u8>, &'b Vec<u8>>],
    ) -> anyhow::Result<()> {
        self.staged.set_many_ref(items)
    }

    fn set_many_vec(&mut self, items: Vec<KVQPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        self.staged.set_many_vec(items)
    }

    fn delete(&mut self, key: &Vec<u8>) -> anyhow::Result<bool> {
        self.staged.delete(key)
    }

    fn delete_many(&mut self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>> {
        self.staged.delete_many(keys)
    }

    fn get_leq(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<&Vec<u8>>> {
        let kv_res = self.get_leq_kv(key, fuzzy_bytes);
        if kv_res.is_err() {
            Err(kv_res.err().unwrap())
        } else {
            let res = kv_res.unwrap();
            if res.is_some() {
                Ok(Some(res.unwrap().value))
            } else {
                Ok(None)
            }
        }
    }

    fn get_leq_kv(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Option<KVQPair<&Vec<u8>, &Vec<u8>>>> {
        let staged_result = self.staged.get_leq_kv(key, fuzzy_bytes);
        if staged_result.is_err() {
            self.backing.get_leq_kv(key, fuzzy_bytes)
        } else {
            let s_result = staged_result.unwrap();
            if s_result.is_none() {
                self.backing.get_leq_kv(key, fuzzy_bytes)
            } else {
                let s_result = s_result.unwrap();

                let backing_result = self.backing.get_leq_kv(key, fuzzy_bytes);
                if backing_result.is_err() {
                    Ok(Some(s_result))
                } else {
                    let b_result = backing_result.unwrap();
                    if b_result.is_none() {
                        Ok(Some(s_result))
                    } else {
                        let b_result = b_result.unwrap();
                        if (&s_result.key).le(&b_result.key) {
                            Ok(Some(b_result))
                        } else {
                            Ok(Some(s_result))
                        }
                    }
                }
            }
        }
    }

    fn get_many_leq(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<&Vec<u8>>>> {
        let mut results: Vec<Option<&Vec<u8>>> = Vec::with_capacity(keys.len());
        for k in keys {
            let r = self.get_leq(k, fuzzy_bytes)?;
            results.push(r);
        }
        Ok(results)
    }

    fn get_many_leq_kv(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<KVQPair<&Vec<u8>, &Vec<u8>>>>> {
        let mut results: Vec<Option<KVQPair<&Vec<u8>, &Vec<u8>>>> = Vec::with_capacity(keys.len());
        for k in keys {
            let r = self.get_leq_kv(k, fuzzy_bytes)?;
            results.push(r);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};

    use crate::{
        common::{
            hash::traits::hasher::{MerkleHasher, PoseidonHasher},
            QHashOut,
        },
        store::kvq::{
            adapters::base::KVQStandardAdapter,
            models::merkle_tree::{merkle_tree::KVQMerkleTreeModel, types::tree::KVQMerkleNodeKey},
            store::simplemem::smstore::KVQSimpleMemoryBackingStore,
        },
    };

    #[test]
    fn test_simple_store() -> anyhow::Result<()> {
        type S = KVQSimpleMemoryBackingStore;
        type TH = PoseidonHasher;
        type F = GoldilocksField;
        type Hash = HashOut<F>;

        const TREE_A_ID: u8 = 1;
        const TREE_B_ID: u8 = 2;
        const TREE_TABLE_TYPE: u16 = 1;
        type KVA = KVQStandardAdapter<S, KVQMerkleNodeKey<TREE_TABLE_TYPE>, Hash>;
        type TreeModel = KVQMerkleTreeModel<TREE_TABLE_TYPE, false, S, KVA, Hash, TH>;

        let mut store = S::new();
        let l0 = KVQMerkleNodeKey::<TREE_TABLE_TYPE> {
            tree_id: TREE_A_ID,
            primary_id: 0,
            secondary_id: 0,
            level: 1,
            index: 0,
            checkpoint_id: 0,
        };
        let zero = Hash::ZERO;
        let v0 = QHashOut::from_values(1, 2, 3, 4).0;
        let expected_root = TH::two_to_one(&v0, &zero);
        let d0 = TreeModel::set_leaf(&mut store, &l0, v0)?;
        //println!("d0: {:?}",d0);
        assert_eq!(d0.new_root, expected_root, "roots do not match");

        let t1_v0 = QHashOut::<F>::from_values(1, 0, 0, 0).0;
        let t1_l0 = KVQMerkleNodeKey::<TREE_TABLE_TYPE> {
            tree_id: TREE_B_ID,
            primary_id: 0,
            secondary_id: 0,
            level: 32,
            index: 1,
            checkpoint_id: 0,
        };
        let t1_d0 = TreeModel::set_leaf(&mut store, &t1_l0, t1_v0)?;
        //println!("t1_d0: {:?}",t1_d0);

        assert_eq!(
            t1_d0.new_root,
            QHashOut::from_string_or_panic(
                "8e57f79e2d660d3fa6f8e8e603d6232cc578766949086917dfe6bd1bb8c2d38a"
            )
            .0
        );

        Ok(())
    }
}
