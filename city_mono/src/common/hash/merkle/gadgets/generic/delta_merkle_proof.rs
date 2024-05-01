use std::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::merkle_proof::compute_merkle_root;
use super::merkle_proof::compute_merkle_root_marked_leaves;
use crate::common::generic::WitnessValueFor;
use crate::common::hash::traits::hasher::GenericCircuitMerkleHasher;
use crate::common::hash::traits::hasher::GenericHashTarget;
use crate::common::qfield::QRichField;
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

impl<H: GenericHashTarget, Hasher: GenericCircuitMerkleHasher<H>>
    GenericDeltaMerkleProofVecGadget<H, Hasher>
{
    pub fn add_virtual_to<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<H> = (0..height).map(|_| H::create_virtual(builder)).collect();

        let old_value = H::create_virtual(builder);
        let new_value = H::create_virtual(builder);
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let old_root =
            compute_merkle_root::<F, D, H, Hasher>(builder, &index_bits, old_value, &siblings);
        let new_root =
            compute_merkle_root::<F, D, H, Hasher>(builder, &index_bits, new_value, &siblings);

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            siblings,
            index,
            _hasher: PhantomData {},
        }
    }
    pub fn add_virtual_to_mark_leaves<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<H> = (0..height).map(|_| H::create_virtual(builder)).collect();

        let old_value = H::create_virtual(builder);
        let new_value = H::create_virtual(builder);
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let old_root = compute_merkle_root_marked_leaves::<F, D, H, Hasher>(
            builder,
            &index_bits,
            old_value,
            &siblings,
            true,
        );
        let new_root = compute_merkle_root_marked_leaves::<F, D, H, Hasher>(
            builder,
            &index_bits,
            new_value,
            &siblings,
            true,
        );

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            siblings,
            index,
            _hasher: PhantomData {},
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
        old_value: &HashValue,
        new_value: &HashValue,
        siblings: &[HashValue],
    ) {
        witness.set_target(self.index, index);
        old_value.set_for_witness(witness, self.old_value);
        new_value.set_for_witness(witness, self.new_value);
        siblings.iter().enumerate().for_each(|(i, sibling)| {
            sibling.set_for_witness(witness, self.siblings[i]);
        });
    }
    pub fn set_witness_le<F: QRichField, HashValue: WitnessValueFor<H, F, false>>(
        &self,
        witness: &mut impl Witness<F>,
        index: F,
        old_value: &HashValue,
        new_value: &HashValue,
        siblings: &[HashValue],
    ) {
        self.set_witness(witness, index, old_value, new_value, siblings)
    }
    pub fn set_witness_be<F: QRichField, HashValue: WitnessValueFor<H, F, false>>(
        &self,
        witness: &mut impl Witness<F>,
        index: F,
        old_value: &HashValue,
        new_value: &HashValue,
        siblings: &[HashValue],
    ) {
        self.set_witness(witness, index, old_value, new_value, siblings)
    }
}
