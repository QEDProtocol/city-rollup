use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::common::{base_types::hash::hash256::Hash256, hash::core::sha256::CoreSha256Hasher};

use super::utils::get_pad_length_sha256_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]

pub struct Sha256DebugScenario {
    pub stark_public_inputs: Vec<u8>,
    pub preimages: Vec<Vec<u8>>,
    pub expected_digests: Vec<Hash256>,
    pub extra_data: Vec<u8>,
}

impl Sha256DebugScenario {
    pub fn from_result(
        preimages: &[Vec<u8>],
        stark_public_inputs_felt: &[GoldilocksField],
    ) -> Self {
        let expected_digests = preimages
            .iter()
            .map(|preimage| CoreSha256Hasher::hash_bytes(preimage))
            .collect::<Vec<_>>();
        let stark_public_inputs = stark_public_inputs_felt
            .iter()
            .map(|field| field.to_canonical_u64() as u8)
            .collect::<Vec<_>>();
        let extra_data_offset = preimages
            .iter()
            .map(|p| get_pad_length_sha256_bytes(p.len()))
            .sum::<usize>();
        let extra_data = (&stark_public_inputs)
            [extra_data_offset..(stark_public_inputs.len() - 32 * preimages.len())]
            .to_vec();

        Self {
            stark_public_inputs,
            preimages: preimages.to_vec(),
            expected_digests,
            extra_data,
        }
    }
    pub fn print(&self) {
        println!("scenario = {};", serde_json::to_string(self).unwrap());
    }
}
