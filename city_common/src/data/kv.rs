use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SimpleKVPair<K, V> {
    pub key: K,
    pub value: V,
}
