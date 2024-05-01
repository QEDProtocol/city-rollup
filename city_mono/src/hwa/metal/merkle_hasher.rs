use std::marker::PhantomData;

use plonky2::{
    field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField},
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    plonk::config::{GenericConfig, GenericConfigMerkleHasher},
};
use serde::Serialize;

use super::poseidon_interleaved::MetalRuntime;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonGoldilocksHWAMetalMerkleHasher(PhantomData<()>);

impl GenericConfigMerkleHasher<GoldilocksField, PoseidonHash>
    for PoseidonGoldilocksHWAMetalMerkleHasher
{
    fn new_merkle_tree(
        leaves: Vec<Vec<GoldilocksField>>,
        cap_height: usize,
    ) -> MerkleTree<GoldilocksField, PoseidonHash> {
        let tree_height = (leaves.len() as f64).log2().ceil() as usize;

        if cap_height == tree_height || tree_height < 13 {
            // use cpu for small trees
            MerkleTree::new(leaves, cap_height)
        } else {
            MetalRuntime::new_merkle_tree(leaves, cap_height)
        }
    }
}
