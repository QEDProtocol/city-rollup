use city_common::binaryhelpers::bytes::read_u32_le_at;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
pub trait CircuitBuilderSignatureHelpers<F: RichField + Extendable<D>, const D: usize> {
    fn bytes33_to_public_key(&mut self, value: &[Target]) -> [Target; 9];
}

pub trait WitnessSignatureHelpers<F: PrimeField64>: Witness<F> {
    fn set_public_key_u32(&mut self, targets: &[Target], public_key_bytes: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessSignatureHelpers<F> for T {
    fn set_public_key_u32(&mut self, targets: &[Target], public_key_bytes: &[u8]) {
        assert_eq!(
            targets.len(),
            9,
            "set_public_key_u32: target input should be 9 targets (1 parity byte + 8 u32s)"
        );
        assert_eq!(
            public_key_bytes.len(),
            33,
            "set_public_key_u32: data input should be 33 bytes (1 parity byte + 32 byte x value)"
        );
        self.set_target(targets[0], F::from_canonical_u8(public_key_bytes[0]));
        for i in 0..8 {
            self.set_target(
                targets[i + 1],
                F::from_canonical_u32(read_u32_le_at(public_key_bytes, 1 + i * 4)),
            );
        }
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
