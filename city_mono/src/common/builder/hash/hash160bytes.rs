use crate::common::generic::{ConnectableTarget, CreatableTarget, SwappableTarget};
use crate::common::hash::traits::hasher::ToTargets;
use crate::common::u32::arithmetic_u32::U32Target;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::hash160::Hash160Target;

pub type Hash160BytesTarget = [Target; 20];

impl ToTargets for Hash160BytesTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.to_vec()
    }
}

pub fn read_hash160_bytes_target_from_array(
    targets: &[Target],
    offset: usize,
) -> Hash160BytesTarget {
    assert!(targets.len() >= offset + 20);
    core::array::from_fn(|i| targets[offset + i])
}

pub trait WitnessHash160<F: PrimeField64>: Witness<F> {
    fn set_hash160_bytes_target(&mut self, target: &Hash160BytesTarget, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash160<F> for T {
    fn set_hash160_bytes_target(&mut self, target: &Hash160BytesTarget, value: &[u8]) {
        target.iter().enumerate().for_each(|(i, t)| {
            // TODO: range check u8?
            self.set_target(*t, F::from_canonical_u8(value[i]));
        });
    }
}

pub trait CircuitBuilderHash160Bytes<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash160_bytes_target(&mut self) -> Hash160BytesTarget;
    fn connect_hash160_bytes(&mut self, x: Hash160BytesTarget, y: Hash160BytesTarget);
    fn select_hash160_bytes(
        &mut self,
        b: BoolTarget,
        x: Hash160BytesTarget,
        y: Hash160BytesTarget,
    ) -> Hash160BytesTarget;
    fn hash160_bytes_to_hash160(&mut self, x: Hash160BytesTarget) -> Hash160Target;
    fn hash160_bytes_from_u32_bits(
        &mut self,
        u32_bits: &[[BoolTarget; 32]; 5],
    ) -> Hash160BytesTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash160Bytes<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_hash160_bytes_target(&mut self) -> Hash160BytesTarget {
        // TODO: range check u8?
        core::array::from_fn(|_| self.add_virtual_target())
    }

    fn connect_hash160_bytes(&mut self, x: Hash160BytesTarget, y: Hash160BytesTarget) {
        x.iter().zip(y.iter()).for_each(|(x, y)| {
            self.connect(*x, *y);
        });
    }

    fn select_hash160_bytes(
        &mut self,
        b: BoolTarget,
        x: Hash160BytesTarget,
        y: Hash160BytesTarget,
    ) -> Hash160BytesTarget {
        core::array::from_fn(|i| self.select(b, x[i], y[i]))
    }

    fn hash160_bytes_to_hash160(&mut self, x: Hash160BytesTarget) -> Hash160Target {
        let result = x
            .chunks_exact(4)
            .map(|chunk| {
                let c160 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[0];
                value = self.mul_add(value, c160, chunk[1]);
                value = self.mul_add(value, c160, chunk[2]);
                U32Target(self.mul_add(value, c160, chunk[3]))
            })
            .collect::<Vec<U32Target>>();
        [result[0], result[1], result[2], result[3], result[4]]
    }

    fn hash160_bytes_from_u32_bits(
        &mut self,
        u32_bits: &[[BoolTarget; 32]; 5],
    ) -> Hash160BytesTarget {
        let all_bits = u32_bits.concat().to_vec();
        all_bits
            .chunks_exact(8)
            .map(|chunk| self.le_sum(chunk.iter()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl SwappableTarget for Hash160BytesTarget {
    fn swap<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        swap: BoolTarget,
        left: Self,
        right: Self,
    ) -> Self {
        builder.select_hash160_bytes(swap, right, left)
    }
}

impl CreatableTarget for Hash160BytesTarget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.add_virtual_hash160_bytes_target()
    }
}

impl ConnectableTarget for Hash160BytesTarget {
    fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        connect_value: Self,
    ) {
        builder.connect_hash160_bytes(*self, connect_value)
    }
}
