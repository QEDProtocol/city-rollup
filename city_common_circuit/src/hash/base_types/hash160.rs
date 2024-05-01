use crate::{
    traits::{ConnectableTarget, CreatableTarget, SwappableTarget, ToTargets, WitnessValueFor},
    u32::{
        arithmetic_u32::{CircuitBuilderU32, U32Target},
        witness::WitnessU32,
    },
};
use city_common::binaryhelpers::bytes::{read_u32_be_at, read_u32_le_at};
use city_crypto::hash::base_types::hash160::Hash160;
use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

pub type Hash160Target = [U32Target; 5];
impl ToTargets for Hash160Target {
    fn to_targets(&self) -> Vec<Target> {
        self.iter().map(|f| f.0).collect()
    }
}
pub trait WitnessHash160<F: PrimeField64>: Witness<F> {
    fn set_hash160_target(&mut self, target: &Hash160Target, value: &[u8]);
    fn set_hash160_target_le(&mut self, target: &Hash160Target, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash160<F> for T {
    fn set_hash160_target(&mut self, target: &Hash160Target, value: &[u8]) {
        self.set_u32_target(target[0], read_u32_be_at(value, 0));
        self.set_u32_target(target[1], read_u32_be_at(value, 4));
        self.set_u32_target(target[2], read_u32_be_at(value, 8));
        self.set_u32_target(target[3], read_u32_be_at(value, 12));
        self.set_u32_target(target[4], read_u32_be_at(value, 16));
    }

    fn set_hash160_target_le(&mut self, target: &Hash160Target, value: &[u8]) {
        self.set_u32_target(target[0], read_u32_le_at(value, 0));
        self.set_u32_target(target[1], read_u32_le_at(value, 4));
        self.set_u32_target(target[2], read_u32_le_at(value, 8));
        self.set_u32_target(target[3], read_u32_le_at(value, 12));
        self.set_u32_target(target[4], read_u32_le_at(value, 16));
    }
}

pub trait CircuitBuilderHash160<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash160_target(&mut self) -> Hash160Target;
    fn connect_hash160(&mut self, x: Hash160Target, y: Hash160Target);
    fn select_hash160(
        &mut self,
        b: BoolTarget,
        x: Hash160Target,
        y: Hash160Target,
    ) -> Hash160Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash160<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_hash160_target(&mut self) -> Hash160Target {
        [
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
            self.add_virtual_u32_target(),
        ]
    }

    fn connect_hash160(&mut self, x: Hash160Target, y: Hash160Target) {
        self.connect_u32(x[0], y[0]);
        self.connect_u32(x[1], y[1]);
        self.connect_u32(x[2], y[2]);
        self.connect_u32(x[3], y[3]);
        self.connect_u32(x[4], y[4]);
    }

    fn select_hash160(
        &mut self,
        b: BoolTarget,
        x: Hash160Target,
        y: Hash160Target,
    ) -> Hash160Target {
        [
            self.select_u32(b, x[0], y[0]),
            self.select_u32(b, x[1], y[1]),
            self.select_u32(b, x[2], y[2]),
            self.select_u32(b, x[3], y[3]),
            self.select_u32(b, x[4], y[4]),
        ]
    }
}

impl SwappableTarget for Hash160Target {
    fn swap<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        swap: BoolTarget,
        left: Self,
        right: Self,
    ) -> Self {
        builder.select_hash160(swap, right, left)
    }
}

impl CreatableTarget for Hash160Target {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.add_virtual_hash160_target()
    }
}

impl ConnectableTarget for Hash160Target {
    fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        connect_value: Self,
    ) {
        builder.connect_hash160(*self, connect_value)
    }
}

impl<F: RichField> WitnessValueFor<Hash160Target, F, false> for Hash160 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash160Target) {
        witness.set_hash160_target_le(&target, &self.0);
    }
}

impl<F: RichField> WitnessValueFor<Hash160Target, F, true> for Hash160 {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: Hash160Target) {
        witness.set_hash160_target(&target, &self.0);
    }
}
