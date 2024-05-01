use std::marker::PhantomData;

use city_common::tree_planner::BinaryTreePlanner;
use city_crypto::field::qfield::QRichField;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::traits::{GenericCircuitMerkleHasher, GenericHashTarget, WitnessValueFor};

pub struct GenericDeltaMerkleProofVecGadget<
    H: GenericHashTarget,
    Hasher: GenericCircuitMerkleHasher<H>,
> {
    pub old_root: H,
    pub old_value: H,

    pub new_root: H,
    pub new_value: H,

    pub siblings: Vec<H>,
    pub index: Target,
    _hasher: PhantomData<Hasher>,
}
pub fn compute_partial_merkle_root_from_leaves_circuit<
    F: QRichField + Extendable<D>,
    const D: usize,
    H: GenericHashTarget,
    Hasher: GenericCircuitMerkleHasher<H>,
>(
    builder: &mut CircuitBuilder<F, D>,
    leaves: &[H],
) -> H {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let levels = BinaryTreePlanner::new(leaves.len()).levels;
    let mut results: Vec<Vec<H>> = vec![vec![]; levels.len()];
    results[0] = leaves.to_vec();
    for i in 0..levels.len() {
        let current = levels[i]
            .iter()
            .map(|j| {
                Hasher::gc_two_to_one(
                    builder,
                    results[j.left_job.level as usize][j.left_job.index as usize],
                    results[j.right_job.level as usize][j.right_job.index as usize],
                )
            })
            .collect::<Vec<H>>();
        results[i + 1] = current;
    }

    results
        .into_iter()
        .last()
        .unwrap()
        .into_iter()
        .last()
        .unwrap()
}
pub fn compute_merkle_root<
    F: QRichField + Extendable<D>,
    const D: usize,
    H: GenericHashTarget,
    Hasher: GenericCircuitMerkleHasher<H>,
>(
    builder: &mut CircuitBuilder<F, D>,
    index_bits: &[BoolTarget],
    value: H,
    siblings: &[H],
) -> H {
    compute_merkle_root_marked_leaves::<F, D, H, Hasher>(
        builder, index_bits, value, siblings, false,
    )
}

pub fn compute_merkle_root_marked_leaves<
    F: QRichField + Extendable<D>,
    const D: usize,
    H: GenericHashTarget,
    Hasher: GenericCircuitMerkleHasher<H>,
>(
    builder: &mut CircuitBuilder<F, D>,
    index_bits: &[BoolTarget],
    value: H,
    siblings: &[H],
    mark_leaves: bool,
) -> H {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        let bit = index_bits[i];
        if mark_leaves && i == 0 {
            current = Hasher::two_to_one_swapped_marked_leaf(builder, current, *sibling, bit);
        } else {
            current = Hasher::two_to_one_swapped(builder, current, *sibling, bit);
        }
    }
    current
}

pub struct GenericMerkleProofVecGadget<H: GenericHashTarget, Hasher: GenericCircuitMerkleHasher<H>>
{
    pub root: H,
    pub value: H,
    pub siblings: Vec<H>,
    pub index: Target,
    _hasher: PhantomData<Hasher>,
}

impl<H: GenericHashTarget, Hasher: GenericCircuitMerkleHasher<H>>
    GenericMerkleProofVecGadget<H, Hasher>
{
    pub fn add_virtual_to<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<H> = (0..height).map(|_| H::create_virtual(builder)).collect();

        let value = H::create_virtual(builder);
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let root = compute_merkle_root::<F, D, H, Hasher>(builder, &index_bits, value, &siblings);

        Self {
            root,
            value,
            siblings,
            index,
            _hasher: PhantomData,
        }
    }
    pub fn add_virtual_to_mark_leaves<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<H> = (0..height).map(|_| H::create_virtual(builder)).collect();

        let value = H::create_virtual(builder);
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let root = compute_merkle_root_marked_leaves::<F, D, H, Hasher>(
            builder,
            &index_bits,
            value,
            &siblings,
            true,
        );

        Self {
            root,
            value,
            siblings,
            index,
            _hasher: PhantomData,
        }
    }

    pub fn set_witness<
        F: QRichField,
        HashValue: WitnessValueFor<H, F, BIG_ENDIAN>,
        const BIG_ENDIAN: bool,
    >(
        &self,
        witness: &mut impl Witness<F>,
        index: F,
        value: &HashValue,
        siblings: &[HashValue],
    ) {
        witness.set_target(self.index, index);
        value.set_for_witness(witness, self.value);
        siblings.iter().enumerate().for_each(|(i, sibling)| {
            sibling.set_for_witness(witness, self.siblings[i]);
        });
    }
    pub fn set_witness_le<F: QRichField, HashValue: WitnessValueFor<H, F, false>>(
        &self,
        witness: &mut impl Witness<F>,
        index: F,
        value: &HashValue,
        siblings: &[HashValue],
    ) {
        self.set_witness(witness, index, value, siblings)
    }
    pub fn set_witness_be<F: QRichField, HashValue: WitnessValueFor<H, F, false>>(
        &self,
        witness: &mut impl Witness<F>,
        index: F,
        value: &HashValue,
        siblings: &[HashValue],
    ) {
        self.set_witness(witness, index, value, siblings)
    }
}

pub fn compute_merkle_root_from_leaves<
    F: QRichField + Extendable<D>,
    const D: usize,
    H: GenericHashTarget,
    Hasher: GenericCircuitMerkleHasher<H>,
>(
    builder: &mut CircuitBuilder<F, D>,
    leaves: &[H],
) -> H {
    if (leaves.len() as f64).log2().ceil() != (leaves.len() as f64).log2().floor() {
        panic!("The length of the merkle tree's leaves array must be a power of 2 (2^n)");
    }
    let num_levels = (leaves.len() as f64).log2().ceil() as usize;
    let mut current = leaves.to_vec();
    for _ in 0..num_levels {
        let tmp = current
            .chunks_exact(2)
            .map(|f| Hasher::gc_two_to_one(builder, f[0], f[1]))
            .collect();
        current = tmp;
    }
    current[0]
}
