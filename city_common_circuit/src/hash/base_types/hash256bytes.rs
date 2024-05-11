use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::hash256::Hash256Target;
use crate::traits::ConnectableTarget;
use crate::traits::CreatableTarget;
use crate::traits::SwappableTarget;
use crate::traits::ToTargets;
use crate::u32::arithmetic_u32::U32Target;

pub type Hash256BytesTarget = [Target; 32];

impl ToTargets for Hash256BytesTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.to_vec()
    }
}

pub fn read_hash256_bytes_target_from_array(
    targets: &[Target],
    offset: usize,
) -> Hash256BytesTarget {
    assert!(targets.len() >= offset + 32);
    core::array::from_fn(|i| targets[offset + i])
}

pub trait WitnessHash256Bytes<F: PrimeField64>: Witness<F> {
    fn set_hash256_bytes_target(&mut self, target: &Hash256BytesTarget, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash256Bytes<F> for T {
    fn set_hash256_bytes_target(&mut self, target: &Hash256BytesTarget, value: &[u8]) {
        target.iter().enumerate().for_each(|(i, t)| {
            // TODO: range check u8?
            self.set_target(*t, F::from_canonical_u8(value[i]));
        });
    }
}

pub trait CircuitBuilderHash256Bytes<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash256_bytes_target(&mut self) -> Hash256BytesTarget;
    fn connect_hash256_bytes(&mut self, x: Hash256BytesTarget, y: Hash256BytesTarget);
    fn select_hash256_bytes(
        &mut self,
        b: BoolTarget,
        x: Hash256BytesTarget,
        y: Hash256BytesTarget,
    ) -> Hash256BytesTarget;
    fn hash256_bytes_to_hash256(&mut self, x: Hash256BytesTarget) -> Hash256Target;
    fn hash256_bytes_to_hashout224(&mut self, x: Hash256BytesTarget) -> HashOutTarget;
    fn hash256_bytes_to_u32_bits(&mut self, x: Hash256BytesTarget) -> [[BoolTarget; 32]; 8];
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash256Bytes<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_hash256_bytes_target(&mut self) -> Hash256BytesTarget {
        // TODO: range check u8?
        core::array::from_fn(|_| self.add_virtual_target())
    }

    fn connect_hash256_bytes(&mut self, x: Hash256BytesTarget, y: Hash256BytesTarget) {
        x.iter().zip(y.iter()).for_each(|(x, y)| {
            self.connect(*x, *y);
        });
    }

    fn select_hash256_bytes(
        &mut self,
        b: BoolTarget,
        x: Hash256BytesTarget,
        y: Hash256BytesTarget,
    ) -> Hash256BytesTarget {
        core::array::from_fn(|i| self.select(b, x[i], y[i]))
    }

    fn hash256_bytes_to_hash256(&mut self, x: Hash256BytesTarget) -> Hash256Target {
        let result = x
            .chunks_exact(4)
            .map(|chunk| {
                let c256 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[3];
                value = self.mul_add(value, c256, chunk[2]);
                value = self.mul_add(value, c256, chunk[1]);
                U32Target(self.mul_add(value, c256, chunk[0]))
            })
            .collect::<Vec<U32Target>>();
        [
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ]
    }

    fn hash256_bytes_to_u32_bits(&mut self, x: Hash256BytesTarget) -> [[BoolTarget; 32]; 8] {
        let zero = self._false();
        let result = x
            .chunks_exact(4)
            .map(|chunk| {
                let mut bits = [zero; 32];
                bits[0..8].copy_from_slice(&self.split_le(chunk[0], 8));
                bits[8..16].copy_from_slice(&self.split_le(chunk[1], 8));
                bits[16..24].copy_from_slice(&self.split_le(chunk[2], 8));
                bits[24..32].copy_from_slice(&self.split_le(chunk[3], 8));
                bits
            })
            .collect::<Vec<_>>();
        [
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ]
    }

    fn hash256_bytes_to_hashout224(&mut self, x: Hash256BytesTarget) -> HashOutTarget {
        let result = x
            .chunks_exact(8)
            .map(|chunk| {
                let c256 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[6];
                value = self.mul_add(value, c256, chunk[5]);
                value = self.mul_add(value, c256, chunk[4]);
                value = self.mul_add(value, c256, chunk[3]);
                value = self.mul_add(value, c256, chunk[2]);
                value = self.mul_add(value, c256, chunk[1]);
                self.mul_add(value, c256, chunk[0])
            })
            .collect::<Vec<Target>>();
        HashOutTarget {
            elements: [result[0], result[1], result[2], result[3]],
        }
    }
}

impl SwappableTarget for Hash256BytesTarget {
    fn swap<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        swap: BoolTarget,
        left: Self,
        right: Self,
    ) -> Self {
        builder.select_hash256_bytes(swap, right, left)
    }
}

impl CreatableTarget for Hash256BytesTarget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.add_virtual_hash256_bytes_target()
    }
}

impl ConnectableTarget for Hash256BytesTarget {
    fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        connect_value: Self,
    ) {
        builder.connect_hash256_bytes(*self, connect_value)
    }
}
