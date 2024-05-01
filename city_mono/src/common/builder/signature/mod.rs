use hashbrown::HashMap;
use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};
pub trait CircuitBuilderSignatureHelpers<F: RichField + Extendable<D>, const D: usize> {
    fn bytes33_to_public_key(&mut self, value: &[Target]) -> [Target; 9];
}

pub trait WitnessSignatureHelpers<F: PrimeField64>: Witness<F> {
    fn set_public_key_u32(&self, public_key_bytes: &[u8; 33], targets: &[Target]) -> Vec<F>;
}

impl<T: Witness<F>, F: PrimeField64> WitnessSignatureHelpers<F> for T {
    fn set_public_key_u32(&self, public_key_bytes: &[u8; 33], targets: &[Target]) -> Vec<F> {
        todo!()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSignatureHelpers<F, D>
    for CircuitBuilder<F, D>
{
    fn bytes33_to_public_key(&mut self, value: &[Target]) -> [Target; 9] {
        let t256 = F::from_canonical_u32(256);

        core::array::from_fn(|i| {
            if i == 0 {
                value[0]
            } else {
                let offset = (i - 1) * 4 + 1;
                let mut result = value[offset + 3];
                result = self.mul_const_add(t256, result, value[offset + 2]);
                result = self.mul_const_add(t256, result, value[offset + 1]);
                result = self.mul_const_add(t256, result, value[offset + 0]);
                result
            }
        })
    }
}
