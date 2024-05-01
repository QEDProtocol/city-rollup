use crate::common::builder::hash::{hash256::Hash256Target, sha256::Sha256Hasher, hash192::Hash192Target, sha256_truncated::Sha256Hasher192};
use super::generic::{delta_merkle_proof::GenericDeltaMerkleProofVecGadget, merkle_proof::GenericMerkleProofVecGadget};

pub type Sha256DeltaMerkleProofVecGadget = GenericDeltaMerkleProofVecGadget<Hash256Target, Sha256Hasher>;
pub type Sha256MerkleProofVecGadget = GenericMerkleProofVecGadget<Hash256Target, Sha256Hasher>;

pub type Sha256x192DeltaMerkleProofVecGadget = GenericDeltaMerkleProofVecGadget<Hash192Target, Sha256Hasher192>;
pub type Sha256x192MerkleProofVecGadget = GenericMerkleProofVecGadget<Hash192Target, Sha256Hasher192>;