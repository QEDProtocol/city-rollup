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
pub trait TargetResolverCore<F: PrimeField64> {
    fn try_resolve_target_or_constant(&self, target: Target) -> Option<F>;
}

impl<F: PrimeField64> TargetResolverCore<F> for HashMap<Target, F> {
    fn try_resolve_target_or_constant(&self, target: Target) -> Option<F> {
        self.get(&target).copied()
    }
}
pub trait CircuitBuilderHelpersCore<F: RichField + Extendable<D>, const D: usize> {
    fn constant_u32_bits(&mut self, value: u32) -> [BoolTarget; 32];
    fn constant_u64_bits(&mut self, value: u64) -> [BoolTarget; 64];
    fn constant_u32_bytes_le(&mut self, value: u32) -> [Target; 4];
    fn constant_u32_bytes_be(&mut self, value: u32) -> [Target; 4];
    fn constant_u64_bytes_le(&mut self, value: u64) -> [Target; 8];
    fn constant_u64_bytes_be(&mut self, value: u64) -> [Target; 8];
    fn split_u64_bytes_le(&mut self, x: Target) -> [Target; 8];
    fn split_u64_bytes_be(&mut self, x: Target) -> [Target; 8];

    fn sum_targets(&mut self, values: &[Target]) -> Target;
    fn le_bytes_to_u32_target(&mut self, bytes: &[Target]) -> Target;
    fn le_bytes_to_u48_target(&mut self, bytes: &[Target]) -> Target;
    fn le_bytes_to_u56_target(&mut self, bytes: &[Target]) -> Target;
    fn le_bytes_to_u64_u56_target(&mut self, bytes: &[Target]) -> Target;

    fn constant_u8(&mut self, value: u8) -> Target;
    fn constant_u32(&mut self, value: u32) -> Target;
    fn constant_u64(&mut self, value: u64) -> Target;
    fn constant_bytes(&mut self, values: &[u8]) -> Vec<Target>;
    fn constant_u32_array(&mut self, values: &[u32]) -> Vec<Target>;
    fn constant_u64_array(&mut self, values: &[u64]) -> Vec<Target>;
    fn constant_felt_array(&mut self, values: &[F]) -> Vec<Target>;
}

pub trait WitnessHelpersCore<F: PrimeField64>: Witness<F> {
    fn resolve_targets_with_constants(
        &self,
        constant_map: &HashMap<Target, F>,
        targets: &[Target],
    ) -> Vec<F>;
    fn resolve_target_with_constants(&self, constant_map: &HashMap<Target, F>, target: Target)
        -> F;
    fn resolve_target_or_constant<R: TargetResolverCore<F>>(
        &self,
        alt_resolver: &R,
        target: Target,
    ) -> F;
    fn resolve_targets_or_constants<R: TargetResolverCore<F>>(
        &self,
        alt_resolver: &R,
        targets: &[Target],
    ) -> Vec<F>;
    fn set_byte_targets(&mut self, targets: &[Target], value: &[u8]);
    fn get_byte_targets(&self, targets: &[Target]) -> Vec<u8>;

    fn set_u32_bytes_le_target(&mut self, targets: &[Target], value: u32);
    fn set_u32_bytes_be_target(&mut self, targets: &[Target], value: u32);
    fn set_u64_bytes_le_target(&mut self, targets: &[Target], value: u64);
    fn set_u64_bytes_be_target(&mut self, targets: &[Target], value: u64);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHelpersCore<F> for T {
    fn set_byte_targets(&mut self, targets: &[Target], value: &[u8]) {
        value
            .iter()
            .zip(targets)
            .for_each(|(b, t)| self.set_target(*t, F::from_canonical_u8(*b)));
    }

    fn get_byte_targets(&self, targets: &[Target]) -> Vec<u8> {
        self.get_targets(targets)
            .iter()
            .map(|n| n.to_canonical_u64() as u8)
            .collect()
    }

    fn set_u32_bytes_le_target(&mut self, targets: &[Target], value: u32) {
        let bytes = value.to_le_bytes();
        self.set_byte_targets(targets, &bytes);
    }

    fn set_u32_bytes_be_target(&mut self, targets: &[Target], value: u32) {
        let bytes = value.to_be_bytes();
        self.set_byte_targets(targets, &bytes);
    }

    fn set_u64_bytes_le_target(&mut self, targets: &[Target], value: u64) {
        let bytes = value.to_le_bytes();
        self.set_byte_targets(targets, &bytes);
    }

    fn set_u64_bytes_be_target(&mut self, targets: &[Target], value: u64) {
        let bytes = value.to_be_bytes();
        self.set_byte_targets(targets, &bytes);
    }

    fn resolve_target_or_constant<R: TargetResolverCore<F>>(
        &self,
        alt_resolver: &R,
        target: Target,
    ) -> F {
        let rt = self.try_get_target(target);
        if rt.is_none() {
            //println!("target empty, trying constant");
            let alt_result = alt_resolver.try_resolve_target_or_constant(target);
            if alt_result.is_none() {
                panic!("cannot resolve target!");
            } else {
                alt_result.unwrap()
            }
        } else {
            rt.unwrap()
        }
    }

    fn resolve_targets_with_constants(
        &self,
        constant_map: &HashMap<Target, F>,
        targets: &[Target],
    ) -> Vec<F> {
        targets
            .iter()
            .map(|target| self.resolve_target_with_constants(constant_map, *target))
            .collect()
    }

    fn resolve_target_with_constants(
        &self,
        constant_map: &HashMap<Target, F>,
        target: Target,
    ) -> F {
        let rt = self.try_get_target(target);
        if rt.is_none() {
            constant_map
                .get(&target)
                .copied()
                .expect("cannot resolve target")
        } else {
            rt.unwrap()
        }
    }

    fn resolve_targets_or_constants<R: TargetResolverCore<F>>(
        &self,
        alt_resolver: &R,
        targets: &[Target],
    ) -> Vec<F> {
        targets
            .iter()
            .map(|target| self.resolve_target_or_constant(alt_resolver, *target))
            .collect()
    }
}
impl<F: RichField + Extendable<D>, const D: usize> TargetResolverCore<F> for CircuitBuilder<F, D> {
    fn try_resolve_target_or_constant(&self, target: Target) -> Option<F> {
        self.target_as_constant(target)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHelpersCore<F, D>
    for CircuitBuilder<F, D>
{
    fn constant_u32_bits(&mut self, value: u32) -> [BoolTarget; 32] {
        core::array::from_fn(|i| {
            if ((value >> i as u32) & 1) == 1 {
                self._true()
            } else {
                self._false()
            }
        })
    }

    fn split_u64_bytes_le(&mut self, x: Target) -> [Target; 8] {
        let result = self.split_le_base::<8>(x, 8);
        [
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ]
    }
    fn split_u64_bytes_be(&mut self, x: Target) -> [Target; 8] {
        let result = self.split_le_base::<8>(x, 8);
        [
            result[7], result[6], result[5], result[4], result[3], result[2], result[1], result[0],
        ]
    }

    fn sum_targets(&mut self, values: &[Target]) -> Target {
        if values.is_empty() {
            self.zero()
        } else {
            let mut sum = values[0];
            for i in 1..values.len() {
                sum = self.add(sum, values[i]);
            }
            sum
        }
    }

    fn constant_u64_bits(&mut self, value: u64) -> [BoolTarget; 64] {
        core::array::from_fn(|i| {
            if ((value >> i as u64) & 1u64) == 1u64 {
                self._true()
            } else {
                self._false()
            }
        })
    }

    fn constant_u32_bytes_le(&mut self, value: u32) -> [Target; 4] {
        let bytes = value.to_le_bytes();
        [
            self.constant(F::from_canonical_u8(bytes[0])),
            self.constant(F::from_canonical_u8(bytes[1])),
            self.constant(F::from_canonical_u8(bytes[2])),
            self.constant(F::from_canonical_u8(bytes[3])),
        ]
    }

    fn constant_u32_bytes_be(&mut self, value: u32) -> [Target; 4] {
        let bytes = value.to_be_bytes();
        [
            self.constant(F::from_canonical_u8(bytes[0])),
            self.constant(F::from_canonical_u8(bytes[1])),
            self.constant(F::from_canonical_u8(bytes[2])),
            self.constant(F::from_canonical_u8(bytes[3])),
        ]
    }

    fn constant_u64_bytes_le(&mut self, value: u64) -> [Target; 8] {
        let bytes = value.to_le_bytes();
        [
            self.constant(F::from_canonical_u8(bytes[0])),
            self.constant(F::from_canonical_u8(bytes[1])),
            self.constant(F::from_canonical_u8(bytes[2])),
            self.constant(F::from_canonical_u8(bytes[3])),
            self.constant(F::from_canonical_u8(bytes[4])),
            self.constant(F::from_canonical_u8(bytes[5])),
            self.constant(F::from_canonical_u8(bytes[6])),
            self.constant(F::from_canonical_u8(bytes[7])),
        ]
    }

    fn constant_u64_bytes_be(&mut self, value: u64) -> [Target; 8] {
        let bytes = value.to_be_bytes();
        [
            self.constant(F::from_canonical_u8(bytes[0])),
            self.constant(F::from_canonical_u8(bytes[1])),
            self.constant(F::from_canonical_u8(bytes[2])),
            self.constant(F::from_canonical_u8(bytes[3])),
            self.constant(F::from_canonical_u8(bytes[4])),
            self.constant(F::from_canonical_u8(bytes[5])),
            self.constant(F::from_canonical_u8(bytes[6])),
            self.constant(F::from_canonical_u8(bytes[7])),
        ]
    }

    fn constant_bytes(&mut self, values: &[u8]) -> Vec<Target> {
        values
            .iter()
            .map(|x| self.constant(F::from_canonical_u8(*x)))
            .collect()
    }

    fn constant_u32_array(&mut self, values: &[u32]) -> Vec<Target> {
        values
            .iter()
            .map(|x| self.constant(F::from_canonical_u32(*x)))
            .collect()
    }

    fn constant_u64_array(&mut self, values: &[u64]) -> Vec<Target> {
        values
            .iter()
            .map(|x| self.constant(F::from_noncanonical_u64(*x)))
            .collect()
    }

    fn constant_felt_array(&mut self, values: &[F]) -> Vec<Target> {
        values.iter().map(|x| self.constant(*x)).collect()
    }

    fn constant_u8(&mut self, value: u8) -> Target {
        self.constant(F::from_canonical_u8(value))
    }

    fn constant_u32(&mut self, value: u32) -> Target {
        self.constant(F::from_canonical_u32(value))
    }

    fn constant_u64(&mut self, value: u64) -> Target {
        self.constant(F::from_noncanonical_u64(value))
    }

    fn le_bytes_to_u32_target(&mut self, bytes: &[Target]) -> Target {
        let t256 = F::from_canonical_u32(256);

        let mut sum = bytes[3];
        sum = self.mul_const_add(t256, sum, bytes[2]);
        sum = self.mul_const_add(t256, sum, bytes[1]);
        sum = self.mul_const_add(t256, sum, bytes[0]);
        sum
    }

    fn le_bytes_to_u64_u56_target(&mut self, bytes: &[Target]) -> Target {
        assert_eq!(
            bytes.len(),
            6,
            "le_bytes_to_u64_u56_target transforms 8 bytes to a u56 target"
        );
        let zero = self.zero();

        // make sure the top byte is zero to prevent overflows
        self.connect(bytes[7], zero);

        let t256 = F::from_canonical_u32(256);

        let mut sum = bytes[6];
        sum = self.mul_const_add(t256, sum, bytes[5]);
        sum = self.mul_const_add(t256, sum, bytes[4]);
        sum = self.mul_const_add(t256, sum, bytes[3]);
        sum = self.mul_const_add(t256, sum, bytes[2]);
        sum = self.mul_const_add(t256, sum, bytes[1]);
        sum = self.mul_const_add(t256, sum, bytes[0]);
        sum
    }

    fn le_bytes_to_u48_target(&mut self, bytes: &[Target]) -> Target {
        assert_eq!(
            bytes.len(),
            6,
            "le_bytes_to_u48_target transforms 6 bytes to a u48 target"
        );
        let t256 = F::from_canonical_u32(256);

        let mut sum = bytes[5];
        sum = self.mul_const_add(t256, sum, bytes[4]);
        sum = self.mul_const_add(t256, sum, bytes[3]);
        sum = self.mul_const_add(t256, sum, bytes[2]);
        sum = self.mul_const_add(t256, sum, bytes[1]);
        sum = self.mul_const_add(t256, sum, bytes[0]);
        sum
    }

    fn le_bytes_to_u56_target(&mut self, bytes: &[Target]) -> Target {
        assert_eq!(
            bytes.len(),
            7,
            "le_bytes_to_u56_target transforms 7 bytes to a u56 target"
        );

        let t256 = F::from_canonical_u32(256);

        let mut sum = bytes[6];
        sum = self.mul_const_add(t256, sum, bytes[5]);
        sum = self.mul_const_add(t256, sum, bytes[4]);
        sum = self.mul_const_add(t256, sum, bytes[3]);
        sum = self.mul_const_add(t256, sum, bytes[2]);
        sum = self.mul_const_add(t256, sum, bytes[1]);
        sum = self.mul_const_add(t256, sum, bytes[0]);
        sum
    }
}
