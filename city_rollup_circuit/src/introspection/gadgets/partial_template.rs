use std::ops::Deref;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::common::builder::core::CircuitBuilderHelpersCore;
pub trait BuilderInputGadget<V> {
    fn add_input_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: V,
    ) -> Self;
}

pub trait BuilderInputGadgetRef<V> {
    fn add_input_virtual_to_ref<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &V,
    ) -> Self;
}

impl<T> BuilderInputGadgetRef<T> for Target {
    fn add_input_virtual_to_ref<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _: &T,
    ) -> Self {
        builder.add_virtual_target()
    }
}
impl<T> BuilderInputGadget<T> for Target {
    fn add_input_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _: T,
    ) -> Self {
        builder.add_virtual_target()
    }
}

impl<E: BuilderInputGadgetRef<T>, T> BuilderInputGadget<&[T]> for Vec<E> {
    fn add_input_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &[T],
    ) -> Self {
        (0..value.len())
            .map(|i| E::add_input_virtual_to_ref(builder, &value[i]))
            .collect()
    }
}

impl<E: BuilderInputGadgetRef<T>, T> BuilderInputGadgetRef<Vec<T>> for Vec<E> {
    fn add_input_virtual_to_ref<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Vec<T>,
    ) -> Self {
        (0..value.len())
            .map(|i| E::add_input_virtual_to_ref(builder, &value[i]))
            .collect()
    }
}

impl<E: BuilderInputGadgetRef<T>, T, const L: usize> BuilderInputGadget<&[T; L]> for [E; L] {
    fn add_input_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &[T; L],
    ) -> Self {
        core::array::from_fn(|i| E::add_input_virtual_to_ref(builder, &value[i]))
    }
}
impl<E: BuilderInputGadgetRef<T>, T, const L: usize> BuilderInputGadgetRef<[T; L]> for [E; L] {
    fn add_input_virtual_to_ref<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &[T; L],
    ) -> Self {
        core::array::from_fn(|i| E::add_input_virtual_to_ref(builder, &value[i]))
    }
}

pub trait WitnessableBy<T> {
    fn constant_circuit<F: RichField + Extendable<D>, const D: usize>(
        value: T,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self;
    fn set_witness<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: T,
        witness: &mut W,
    );
}

pub trait WitnessableByRef<T> {
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &T,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self;
    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &T,
        witness: &mut W,
    );
}

impl WitnessableByRef<u8> for Target {
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &u8,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.constant_u8(*value)
    }

    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &u8,
        witness: &mut W,
    ) {
        witness.set_target(*self, F::from_canonical_u8(*value));
    }
}

impl WitnessableByRef<u32> for Target {
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &u32,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.constant_u32(*value)
    }

    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &u32,
        witness: &mut W,
    ) {
        witness.set_target(*self, F::from_canonical_u32(*value));
    }
}

impl WitnessableByRef<u64> for Target {
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &u64,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        builder.constant_u64(*value)
    }

    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &u64,
        witness: &mut W,
    ) {
        witness.set_target(*self, F::from_noncanonical_u64(*value));
    }
}

impl<T: WitnessableByRef<V>, V> WitnessableBy<&V> for T {
    fn constant_circuit<F: RichField + Extendable<D>, const D: usize>(
        value: &V,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        T::constant_circuit_ref(value, builder)
    }

    fn set_witness<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &V,
        witness: &mut W,
    ) {
        T::set_witness_ref(self, value, witness)
    }
}

impl<T: WitnessableByRef<V> + BuilderInputGadgetRef<V>, V> WitnessableBy<&[V]> for Vec<T> {
    fn constant_circuit<F: RichField + Extendable<D>, const D: usize>(
        value: &[V],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        value
            .into_iter()
            .map(|v| T::constant_circuit(&v, builder))
            .collect()
    }

    fn set_witness<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &[V],
        witness: &mut W,
    ) {
        value
            .into_iter()
            .enumerate()
            .map(|(i, v)| T::set_witness(&self[i], &v, witness))
            .collect()
    }
}

impl<T: WitnessableByRef<V> + BuilderInputGadgetRef<V>, V> WitnessableByRef<Vec<V>> for Vec<T> {
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &Vec<V>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        value
            .into_iter()
            .map(|v| T::constant_circuit(&v, builder))
            .collect()
    }

    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &Vec<V>,
        witness: &mut W,
    ) {
        value
            .into_iter()
            .enumerate()
            .map(|(i, v)| T::set_witness(&self[i], &v, witness))
            .collect()
    }
}
impl<
        T: WitnessableByRef<V> + BuilderInputGadgetRef<V> + BuilderInputGadget<V>,
        V,
        const L: usize,
    > WitnessableByRef<[V; L]> for [T; L]
{
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &[V; L],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        core::array::from_fn(|i| T::constant_circuit_ref(&value[i], builder))
    }

    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &[V; L],
        witness: &mut W,
    ) {
        value
            .into_iter()
            .enumerate()
            .map(|(i, v)| T::set_witness(&self[i], v, witness))
            .collect()
    }
}
pub trait PartialTemplateWitnessableBy<T, K>: WitnessableByRef<T> {
    fn get_circuit_template<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &T,
        witness_keys: &[K],
    ) -> Self;

    fn set_witness_template<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &T,
        witness: &mut W,
    );
    fn resolve_field<
        P: WitnessableByRef<V> + BuilderInputGadgetRef<V>,
        F: RichField + Extendable<D>,
        const D: usize,
        V,
    >(
        builder: &mut CircuitBuilder<F, D>,
        is_witness: bool,
        value: &V,
    ) -> P {
        if is_witness {
            P::add_input_virtual_to_ref(builder, value)
        } else {
            P::constant_circuit_ref(&value, builder)
        }
    }
}

#[derive(PartialEq, Eq, Clone, Ord, PartialOrd, Debug)]
pub enum BlockDefGadgetPartialMask {
    BlockNumber,
    BlockTime,
    BlockHash,
    BlockData,
}
pub struct BlockDefGadget {
    pub block_number: Target,
    pub block_time: Target,
    pub block_hash: [Target; 32],
    pub block_data: Vec<Target>,
}
impl BuilderInputGadgetRef<BlockDef> for BlockDefGadget {
    fn add_input_virtual_to_ref<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &BlockDef,
    ) -> Self {
        Self {
            block_number: Target::add_input_virtual_to(builder, &value.block_number),
            block_time: Target::add_input_virtual_to(builder, &value.block_time),
            block_hash: <[Target; 32]>::add_input_virtual_to_ref(builder, &value.block_hash),
            block_data: <Vec<Target>>::add_input_virtual_to(builder, &value.block_data),
        }
    }
}

pub struct BlockDef {
    pub block_number: u32,
    pub block_time: u64,
    pub block_hash: [u8; 32],
    pub block_data: Vec<u8>,
}

impl WitnessableByRef<BlockDef> for BlockDefGadget {
    fn constant_circuit_ref<F: RichField + Extendable<D>, const D: usize>(
        value: &BlockDef,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            block_number: Target::constant_circuit(&value.block_number, builder),
            block_time: Target::constant_circuit(&value.block_time, builder),
            block_hash: <[Target; 32]>::constant_circuit(&value.block_hash, builder),
            block_data: <Vec<Target>>::constant_circuit(&value.block_data, builder),
        }
    }

    fn set_witness_ref<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &BlockDef,
        witness: &mut W,
    ) {
        self.block_number.set_witness(&value.block_number, witness);
        self.block_time.set_witness(&value.block_time, witness);
        self.block_hash.set_witness(&value.block_hash, witness);
        self.block_data.set_witness(&value.block_data, witness);
    }
}

impl PartialTemplateWitnessableBy<BlockDef, BlockDefGadgetPartialMask> for BlockDefGadget {
    fn get_circuit_template<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &BlockDef,
        witness_keys: &[BlockDefGadgetPartialMask],
    ) -> BlockDefGadget {
        Self {
            block_number: Self::resolve_field(
                builder,
                witness_keys.contains(&BlockDefGadgetPartialMask::BlockNumber),
                &value.block_number,
            ),
            block_time: Self::resolve_field(
                builder,
                witness_keys.contains(&BlockDefGadgetPartialMask::BlockTime),
                &value.block_time,
            ),
            block_hash: Self::resolve_field(
                builder,
                witness_keys.contains(&BlockDefGadgetPartialMask::BlockHash),
                &value.block_hash,
            ),
            block_data: Self::resolve_field(
                builder,
                witness_keys.contains(&BlockDefGadgetPartialMask::BlockData),
                &value.block_data,
            ),
        }
    }

    fn set_witness_template<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        value: &BlockDef,
        witness: &mut W,
    ) {
        self.block_number
            .set_witness_ref(&value.block_number, witness);
        self.block_time.set_witness_ref(&value.block_time, witness);
        self.block_hash.set_witness_ref(&value.block_hash, witness);
        self.block_data.set_witness_ref(&value.block_data, witness);
    }
}
