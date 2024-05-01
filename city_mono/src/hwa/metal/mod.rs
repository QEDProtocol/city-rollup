use plonky2::{
    field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField},
    hash::poseidon::PoseidonHash,
    plonk::config::GenericConfig,
};
use serde::Serialize;

use self::merkle_hasher::PoseidonGoldilocksHWAMetalMerkleHasher;

mod merkle_hasher;
mod poseidon_interleaved;

/// Configuration using GPU Poseidon over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonGoldilocksHWAMetalConfig;

impl GenericConfig<2> for PoseidonGoldilocksHWAMetalConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonHash;
    type InnerHasher = PoseidonHash;
    type MerkleHasher = PoseidonGoldilocksHWAMetalMerkleHasher;
}
