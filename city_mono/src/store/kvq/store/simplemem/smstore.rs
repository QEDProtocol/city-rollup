use std::collections::BTreeMap;

use crate::store::kvq::traits::{KVQBinaryStore, KVQPair};

pub struct KVQSimpleMemoryBackingStore {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl KVQSimpleMemoryBackingStore {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl KVQBinaryStore for KVQSimpleMemoryBackingStore {
    fn get_exact(&self, key: &Vec<u8>) -> anyhow::Result<&Vec<u8>> {
        match self.map.get(key) {
            Some(v) => Ok(v),
            None => anyhow::bail!("Key not found"),
        }
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
        self.map.insert(key, value);
        Ok(())
    }

    fn set_ptr(&mut self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()> {
        self.map.insert(key.clone(), value.clone());
        Ok(())
    }

    fn set_many_ref<'a>(
        &mut self,
        items: &[KVQPair<&'a Vec<u8>, &'a Vec<u8>>],
    ) -> anyhow::Result<()> {
        for item in items {
            self.map.insert(item.key.clone(), item.value.clone());
        }
        Ok(())
    }

    fn set_many_vec(&mut self, items: Vec<KVQPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        for item in items {
            self.map.insert(item.key.clone(), item.value.clone());
        }
        Ok(())
    }

    fn delete(&mut self, key: &Vec<u8>) -> anyhow::Result<bool> {
        match self.map.remove(key) {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    fn delete_many(&mut self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>> {
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            let r = self.delete(key)?;
            result.push(r);
        }
        Ok(result)
    }

    fn get_leq(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<&Vec<u8>>> {
        let key_end = key.to_vec();
        let mut base_key = key.to_vec();
        let key_len = base_key.len();
        if fuzzy_bytes > key_len {
            return Err(anyhow::anyhow!(
                "Fuzzy bytes must be less than or equal to key length"
            ));
        }
        let mut sum_end = 0u32;
        for i in 0..fuzzy_bytes {
            sum_end += key_end[key_len - i - 1] as u32;
            base_key[key_len - i - 1] = 0;
        }

        if sum_end == 0 {
            Ok(self.map.get(key))
        } else {
            let rq = self.map.range(base_key..key_end).next_back();
            if rq.is_none() {
                Ok(None)
            } else {
                let p = rq.unwrap().1;

                Ok(Some(p))
            }
        }
    }

    fn get_leq_kv(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Option<KVQPair<&Vec<u8>, &Vec<u8>>>> {
        let key_end = key.to_vec();
        let mut base_key = key.to_vec();
        let key_len = base_key.len();
        if fuzzy_bytes > key_len {
            return Err(anyhow::anyhow!(
                "Fuzzy bytes must be less than or equal to key length"
            ));
        }

        for i in 0..fuzzy_bytes {
            base_key[key_len - i - 1] = 0;
        }
        let rq = self.map.range(base_key..key_end).next_back();

        if rq.is_none() {
            Ok(None)
        } else {
            let p = rq.unwrap();
            Ok(Some(KVQPair {
                key: p.0,
                value: p.1,
            }))
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
impl KVQSimpleMemoryBackingStore {
    // fn simple_store_mem_snapshot_slow(&self)->
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
            traits::KVQBinaryStore,
        },
    };

    use super::KVQSimpleMemoryBackingStore;

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
            checkpoint_id: 1,
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
            checkpoint_id: 1,
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

    #[test]
    fn test_store_2() -> anyhow::Result<()> {
        type S = KVQSimpleMemoryBackingStore;
        type TH = PoseidonHasher;
        type F = GoldilocksField;
        type Hash = HashOut<F>;

        const TREE_A_ID: u8 = 1;
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
        let l1 = KVQMerkleNodeKey::<TREE_TABLE_TYPE> {
            tree_id: TREE_A_ID,
            primary_id: 0,
            secondary_id: 0,
            level: 1,
            index: 1,
            checkpoint_id: 0,
        };
        let zero = Hash::ZERO;
        let v0 = QHashOut::from_values(1, 2, 3, 4).0;
        let v1 = QHashOut::from_values(5, 6, 7, 8).0;
        let expected_root = TH::two_to_one(&v0, &v1);
        let d0 = TreeModel::set_leaf(&mut store, &l0, v0)?;
        println!("d0: {:?}", d0);
        let result = store
            .get_exact(&vec![
                0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
            .unwrap();
        println!("result: {:?}", result);
        let result = store
            .get_leq(
                &vec![
                    0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                8,
            )
            .unwrap();
        println!("result2: {:?}", result);

        let f0 = TreeModel::get_leaf(&mut store, &l0).unwrap();
        println!("f0: {:?}", f0);

        let d1 = TreeModel::set_leaf(&mut store, &l1, v1)?;
        println!("d1: {:?}", d1);

        //println!("d0: {:?}",d0);
        assert_eq!(d1.new_root, expected_root, "roots do not match");

        Ok(())
    }
}
