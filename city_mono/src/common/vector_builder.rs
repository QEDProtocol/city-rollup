use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::{
    btc::data::varuint::encode_varuint, common::builder::hash::hash256bytes::Hash256BytesTarget,
};

use super::{
    builder::{core::CircuitBuilderHelpersCore, hash::hash160bytes::Hash160BytesTarget},
    u32::arithmetic_u32::{CircuitBuilderU32, U32Target},
};
use core::fmt::Debug;
pub trait VectorBuilderConfig {
    type TElement: Sized + Copy + Debug + Clone;
    type TU32: Sized + Copy + Debug + Clone;
    type TU64: Sized + Copy + Debug + Clone;
    type THash256: Sized + Copy + Debug + Clone;
    type THash160: Sized + Copy + Debug + Clone;
}
#[derive(Clone, Debug)]
pub struct ByteTargetVectorBuilder {
    pub data: Vec<Target>,
}

impl ByteTargetVectorBuilder {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn write(&mut self, target: Target) -> &mut Self {
        self.data.push(target);
        self
    }

    pub fn write_slice(&mut self, targets: &[Target]) -> &mut Self {
        self.data.extend_from_slice(targets);
        self
    }
    pub fn write_constant_bytes<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        data: &[u8],
    ) -> &mut Self {
        self.data.extend_from_slice(&builder.constant_bytes(data));
        self
    }
    pub fn write_u32_bytes_be<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: U32Target,
    ) -> &mut Self {
        self.write_slice(&builder.split_u32_bytes_be(x));
        self
    }
    pub fn write_u32_bytes_le<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: U32Target,
    ) -> &mut Self {
        self.write_slice(&builder.split_u32_bytes(x));
        self
    }
    pub fn write_u64_bytes_be<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: Target,
    ) -> &mut Self {
        let mut tmp = builder.split_le_base::<8>(x, 8);
        tmp.reverse();
        self.write_slice(&tmp);
        self
    }
    pub fn write_u64_bytes_le<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: Target,
    ) -> &mut Self {
        self.write_slice(&builder.split_le_base::<8>(x, 8));
        self
    }

    pub fn write_target_vector(&mut self, target_vector: &ByteTargetVectorBuilder) -> &mut Self {
        self.data.extend_from_slice(&target_vector.data);
        self
    }
    pub fn write_hash160_bytes(&mut self, hash: Hash160BytesTarget) -> &mut Self {
        self.data.extend_from_slice(&hash);
        self
    }
    pub fn write_hash256_bytes(&mut self, hash: Hash256BytesTarget) -> &mut Self {
        self.data.extend_from_slice(&hash);
        self
    }
    pub fn write_constant_u8<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: u8,
    ) -> &mut Self {
        self.data.push(builder.constant(F::from_canonical_u8(x)));
        self
    }

    pub fn write_constant_u32_le<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: u32,
    ) -> &mut Self {
        self.data
            .extend_from_slice(&builder.constant_u32_bytes_le(x));
        self
    }

    pub fn write_constant_u32_be<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: u32,
    ) -> &mut Self {
        self.data
            .extend_from_slice(&builder.constant_u32_bytes_be(x));
        self
    }
    pub fn write_constant_u64_le<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: u64,
    ) -> &mut Self {
        self.data
            .extend_from_slice(&builder.constant_u64_bytes_le(x));
        self
    }

    pub fn write_constant_u64_be<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: u64,
    ) -> &mut Self {
        self.data
            .extend_from_slice(&builder.constant_u64_bytes_be(x));
        self
    }

    pub fn write_constant_varuint<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        x: u64,
    ) -> &mut Self {
        self.data
            .extend_from_slice(&builder.constant_bytes(&encode_varuint(x)));
        self
    }
    pub fn write_var_slice<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        byte_targets: &[Target],
    ) -> &mut Self {
        self.write_constant_varuint(builder, byte_targets.len() as u64)
            .write_slice(byte_targets)
    }
    pub fn to_targets_vec(&self) -> Vec<Target> {
        self.data.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ByteVectorBuilder {
    pub data: Vec<u8>,
}

impl ByteVectorBuilder {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn write(&mut self, x: u8) {
        self.data.push(x);
    }

    pub fn write_slice(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }
    pub fn write_u32_bytes_be(&mut self, x: u32) {
        self.write_slice(&x.to_be_bytes());
    }
    pub fn write_u32_bytes_le(&mut self, x: u32) {
        self.write_slice(&x.to_be_bytes());
    }

    pub fn write_vector_builder(&mut self, target_vector: &ByteVectorBuilder) {
        self.data.extend_from_slice(&target_vector.data);
    }
}
