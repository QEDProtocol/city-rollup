use std::collections::HashMap;

use city_crypto::hash::base_types::hash256::Hash256;


#[derive(Clone, Debug)]
pub struct UserProverWorkerStore {
    pub results: HashMap<Hash256, Vec<u8>>,
}
impl UserProverWorkerStore {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }
    pub fn get_result(&self, key: &Hash256) -> Option<&Vec<u8>> {
        self.results.get(key)
    }
    pub fn get_result_and_clear(&mut self, key: &Hash256) -> Option<Vec<u8>> {
        self.results.remove(key)
    }
    pub fn set_result(&mut self, key: Hash256, value: Vec<u8>) {
        self.results.insert(key, value);
    }
}