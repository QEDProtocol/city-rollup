use plonky2::{
    field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField},
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericConfig, GenericConfigStandardMerkleHasher},
};
use serde::Serialize;

// cpu fallback in case no hardware acceleration is available
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonGoldilocksHWAFallbackConfig;

impl GenericConfig<2> for PoseidonGoldilocksHWAFallbackConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonHash;
    type InnerHasher = PoseidonHash;
    type MerkleHasher = GenericConfigStandardMerkleHasher<Self::F, Self::Hasher>;
}
