use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::binaryhelpers::bytes::{read_u32_be_at, read_u32_le_at};
use crate::common::generic::{ConnectableTarget, CreatableTarget, SwappableTarget};
use crate::common::hash::traits::hasher::ToTargets;
use crate::common::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::common::u32::witness::WitnessU32;

pub type Hash256Target = [U32Target; 8];

impl ToTargets for Hash256Target {
    fn to_targets(&self) -> Vec<Target> {
        self.iter().map(|f| f.0).collect()
    }
}

pub trait WitnessHash256<F: PrimeField64>: Witness<F> {
    fn set_hash256_target(&mut self, target: &Hash256Target, value: &[u8]);
    fn set_hash256_target_le(&mut self, target: &Hash256Target, value: &[u8]);
    fn set_hash256_target_u32(&mut self, target: &Hash256Target, value: &[u32]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash256<F> for T {
    fn set_hash256_target_u32(&mut self, target: &Hash256Target, value: &[u32]) {
        self.set_u32_target(target[0], value[0]);
        self.set_u32_target(target[1], value[1]);
        self.set_u32_target(target[2], value[2]);
        self.set_u32_target(target[3], value[3]);

        self.set_u32_target(target[4], value[4]);
        self.set_u32_target(target[5], value[5]);
        self.set_u32_target(target[6], value[6]);
        self.set_u32_target(target[7], value[7]);
    }

    fn set_hash256_target(&mut self, target: &Hash256Target, value: &[u8]) {
        self.set_u32_target(target[0], read_u32_be_at(value, 0));
        self.set_u32_target(target[1], read_u32_be_at(value, 4));
        self.set_u32_target(target[2], read_u32_be_at(value, 8));
        self.set_u32_target(target[3], read_u32_be_at(value, 12));
        self.set_u32_target(target[4], read_u32_be_at(value, 16));
        self.set_u32_target(target[5], read_u32_be_at(value, 20));
        self.set_u32_target(target[6], read_u32_be_at(value, 24));
        self.set_u32_target(target[7], read_u32_be_at(value, 28));
    }

    fn set_hash256_target_le(&mut self, target: &Hash256Target, value: &[u8]) {
        self.set_u32_target(target[0], read_u32_le_at(value, 0));
        self.set_u32_target(target[1], read_u32_le_at(value, 4));
        self.set_u32_target(target[2], read_u32_le_at(value, 8));
        self.set_u32_target(target[3], read_u32_le_at(value, 12));
        self.set_u32_target(target[4], read_u32_le_at(value, 16));
        self.set_u32_target(target[5], read_u32_le_at(value, 20));
        self.set_u32_target(target[6], read_u32_le_at(value, 24));
        self.set_u32_target(target[7], read_u32_le_at(value, 28));
    }
}

pub trait CircuitBuilderHash<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash256_target(&mut self) -> Hash256Target;
    fn connect_hash256(&mut self, x: Hash256Target, y: Hash256Target);
    fn select_hash256(
        &mut self,
        b: BoolTarget,
        x: Hash256Target,
        y: Hash256Target,
    ) -> Hash256Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_hash256_target(&mut self) -> Hash256Target {
        [
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
        ]
    }

    fn connect_hash256(&mut self, x: Hash256Target, y: Hash256Target) {
        self.connect_u32(x[0], y[0]);
        self.connect_u32(x[1], y[1]);
        self.connect_u32(x[2], y[2]);
        self.connect_u32(x[3], y[3]);
        self.connect_u32(x[4], y[4]);
        self.connect_u32(x[5], y[5]);
        self.connect_u32(x[6], y[6]);
        self.connect_u32(x[7], y[7]);
    }

    fn select_hash256(
        &mut self,
        b: BoolTarget,
        x: Hash256Target,
        y: Hash256Target,
    ) -> Hash256Target {
        [
            self.select_u32(b, x[0], y[0]),
            self.select_u32(b, x[1], y[1]),
            self.select_u32(b, x[2], y[2]),
            self.select_u32(b, x[3], y[3]),
            self.select_u32(b, x[4], y[4]),
            self.select_u32(b, x[5], y[5]),
            self.select_u32(b, x[6], y[6]),
            self.select_u32(b, x[7], y[7]),
        ]
    }
}

impl SwappableTarget for Hash256Target {
    fn swap<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        swap: BoolTarget,
        left: Self,
        right: Self,
    ) -> Self {
        builder.select_hash256(swap, right, left)
    }
}

impl CreatableTarget for Hash256Target {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.add_virtual_hash256_target()
    }
}

impl ConnectableTarget for Hash256Target {
    fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        connect_value: Self,
    ) {
        builder.connect_hash256(*self, connect_value)
    }
}
