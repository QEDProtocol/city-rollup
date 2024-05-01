use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct HashAcceleratorConfig {
    pub preimage_lengths: Vec<usize>,
}

impl HashAcceleratorConfig {
    pub fn from_preimage_lengths(lengths: &[usize]) -> Self {
        Self {
            preimage_lengths: lengths.to_vec(),
        }
    }
}
