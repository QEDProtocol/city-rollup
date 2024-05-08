use super::generic::delta_merkle_proof::GenericDeltaMerkleProofVecGadget;
use super::generic::merkle_proof::GenericMerkleProofVecGadget;
use crate::builder::hash::sha256::Sha256Hasher;
use crate::builder::hash::sha256_truncated::Sha256Hasher192;
use crate::hash::base_types::hash192::Hash192Target;
use crate::hash::base_types::hash256::Hash256Target;

pub type Sha256DeltaMerkleProofVecGadget =
    GenericDeltaMerkleProofVecGadget<Hash256Target, Sha256Hasher>;
pub type Sha256MerkleProofVecGadget = GenericMerkleProofVecGadget<Hash256Target, Sha256Hasher>;

pub type Sha256x192DeltaMerkleProofVecGadget =
    GenericDeltaMerkleProofVecGadget<Hash192Target, Sha256Hasher192>;
pub type Sha256x192MerkleProofVecGadget =
    GenericMerkleProofVecGadget<Hash192Target, Sha256Hasher192>;
