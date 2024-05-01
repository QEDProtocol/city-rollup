use std::fmt::Display;

use hex::FromHexError;
use plonky2::{hash::hash_types::RichField, iop::witness::Witness};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::common::{
    builder::hash::hash160::{Hash160Target, WitnessHash160},
    generic::WitnessValueFor,
    hash::merkle::helpers::merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
pub struct Hash160(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 20]);

impl Hash160 {
    /// .
    ///
    /// # Panics
    ///
    /// Panics if .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 20);
        let mut array = [0u8; 20];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
/*
fn read_u32_in_field_from_bytes_be<F: RichField>(bytes: &[u8; 20], index: usize) -> F {
    F::from_noncanonical_u64(
        (bytes[index] as u64) << 24
          | (bytes[index + 1] as u64) << 16
          | (bytes[index + 2] as u64) << 8
          | (bytes[index + 3] as u64),
    )
}

fn read_u32_in_field_from_bytes_le<F: RichField>(bytes: &[u8; 20], index: usize) -> F {
    F::from_noncanonical_u64(
        (bytes[index + 3] as u64) << 24
          | (bytes[index + 2] as u64) << 16
          | (bytes[index + 1] as u64) << 8
          | (bytes[index] as u64),
    )
}
*/
impl Hash160 {}

pub type MerkleProof160 = MerkleProofCore<Hash160>;
pub type DeltaMerkleProof160 = DeltaMerkleProofCore<Hash160>;
/*
impl MerkleProofTruncatedSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHash160<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &MerkleProof160,
    ) {
        witness.set_hash160_target(&self.value, &merkle_proof.value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash160_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl DeltaMerkleProofTruncatedSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHash160<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &DeltaMerkleProof160,
    ) {
        witness.set_hash160_target(&self.old_value, &merkle_proof.old_value.0);
        witness.set_hash160_target(&self.new_value, &merkle_proof.new_value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash160_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}
*/

impl<F: RichField> WitnessValueFor<Hash160Target, F, false> for Hash160 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash160Target) {
        witness.set_hash160_target_le(&target, &self.0);
    }
}

impl<F: RichField> WitnessValueFor<Hash160Target, F, true> for Hash160 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash160Target) {
        witness.set_hash160_target(&target, &self.0);
    }
}
