use core::fmt;
use std::error::Error;
use std::marker::PhantomData;

use ff::Field as ff_Field;
use ff::PrimeField;
use num::BigUint;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::hash::poseidon::PoseidonPermutation;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::GenericConfigStandardMerkleHasher;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::Hasher;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::bls12_381::fr::Fr;
use crate::bls12_381::fr::FrRepr;
use crate::bls12_381::poseidon::permution;
use crate::bls12_381::poseidon::GOLDILOCKS_ELEMENTS;
use crate::bls12_381::poseidon::RATE;

/// Configuration using Poseidon BN128 over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonBLS12381GoldilocksConfig;
impl GenericConfig<2> for PoseidonBLS12381GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonBLS12381Hash;
    type InnerHasher = PoseidonHash;
    type MerkleHasher = GenericConfigStandardMerkleHasher<Self::F, Self::Hasher>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonBLS12381HashOut<F: Field> {
    pub value: Fr,
    _phantom: PhantomData<F>,
}

fn hash_out_to_bytes<F: Field>(hash: PoseidonBLS12381HashOut<F>) -> Vec<u8> {
    let binding = hash.value.to_repr();
    let limbs = binding.as_ref();
    limbs.to_vec()
}

impl<F: RichField> GenericHashOut<F> for PoseidonBLS12381HashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        hash_out_to_bytes(*self)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let sized_bytes: [u8; 32] = bytes.try_into().unwrap();
        let fr_repr = FrRepr(sized_bytes);
        let fr = Fr::from_repr(fr_repr).unwrap();

        Self {
            value: fr,
            _phantom: PhantomData,
        }
    }

    fn to_vec(&self) -> Vec<F> {
        let bytes = hash_out_to_bytes(*self);
        bytes
            // Chunks of 7 bytes since 8 bytes would allow collisions.
            .chunks(7)
            .map(|bytes| {
                let mut arr = [0; 8];
                arr[..bytes.len()].copy_from_slice(bytes);
                F::from_canonical_u64(u64::from_le_bytes(arr))
            })
            .collect()
    }
}

impl<F: RichField> Serialize for PoseidonBLS12381HashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Output the hash as a bigint string.
        let binding = self.value.to_repr();
        let limbs = binding.as_ref();

        let big_int = BigUint::from_bytes_le(limbs);
        serializer.serialize_str(big_int.to_str_radix(10).as_str())
    }
}

impl<'de, F: RichField> Deserialize<'de> for PoseidonBLS12381HashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PoseidonBLS12381HashOutVisitor;

        impl<'a> Visitor<'a> for PoseidonBLS12381HashOutVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string with integer value within BN128 scalar field")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.to_string())
            }
        }

        let deserialized_str = deserializer
            .deserialize_str(PoseidonBLS12381HashOutVisitor)
            .unwrap();
        let big_int = BigUint::parse_bytes(deserialized_str.as_bytes(), 10).unwrap();

        let mut bytes = big_int.to_bytes_le();
        for _i in bytes.len()..32 {
            bytes.push(0);
        }

        let sized_bytes: [u8; 32] = bytes.try_into().unwrap();
        let fr_repr = FrRepr(sized_bytes);
        let fr = Fr::from_repr(fr_repr).unwrap();

        Ok(Self {
            value: fr,
            _phantom: PhantomData,
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonBLS12381Hash;
impl<F: RichField> Hasher<F> for PoseidonBLS12381Hash {
    const HASH_SIZE: usize = 32; // Hash output is 4 limbs of u64
    type Hash = PoseidonBLS12381HashOut<F>;
    type Permutation = PoseidonPermutation<F>;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        let mut state = [Fr::ZERO; 4];

        state[0] = Fr::ZERO;
        for rate_chunk in input.chunks(RATE * 3) {
            for (j, bls12381chunk) in rate_chunk.chunks(3).enumerate() {
                let mut bytes = bls12381chunk[0].to_canonical_u64().to_le_bytes().to_vec();

                for gl_element in bls12381chunk.iter().skip(1) {
                    let chunk_bytes = gl_element.to_canonical_u64().to_le_bytes();
                    bytes.extend_from_slice(&chunk_bytes);
                }

                for _i in bytes.len()..32 {
                    bytes.push(0);
                }

                let sized_bytes: [u8; 32] = bytes.try_into().unwrap();
                let fr_repr = FrRepr(sized_bytes);
                state[j + 1] = Fr::from_repr(fr_repr).unwrap();
            }
            permution(&mut state);
        }

        PoseidonBLS12381HashOut {
            value: state[0],
            _phantom: PhantomData,
        }
    }

    fn hash_pad(input: &[F]) -> Self::Hash {
        let mut padded_input = input.to_vec();
        padded_input.push(F::ONE);
        while (padded_input.len() + 1) % (RATE * GOLDILOCKS_ELEMENTS) != 0 {
            padded_input.push(F::ZERO);
        }
        padded_input.push(F::ONE);
        Self::hash_no_pad(&padded_input)
    }

    fn hash_or_noop(inputs: &[F]) -> Self::Hash {
        if inputs.len() * 8 <= GOLDILOCKS_ELEMENTS * 8 {
            let mut inputs_bytes = vec![0u8; 32];
            for i in 0..inputs.len() {
                inputs_bytes[i * 8..(i + 1) * 8]
                    .copy_from_slice(&inputs[i].to_canonical_u64().to_le_bytes());
            }
            Self::Hash::from_bytes(&inputs_bytes)
        } else {
            Self::hash_no_pad(inputs)
        }
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let mut state = [Fr::ZERO, Fr::ZERO, left.value, right.value];
        permution(&mut state);

        PoseidonBLS12381HashOut {
            value: state[0],
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_byte_methods() {
        type F = GoldilocksField;

        let fr = Fr::from_str_vartime(
            "11575173631114898451293296430061690731976535592475236587664058405912382527658",
        )
        .unwrap();
        let hash = PoseidonBLS12381HashOut::<F> {
            value: fr,
            _phantom: PhantomData,
        };

        let bytes = hash.to_bytes();

        let hash_from_bytes = PoseidonBLS12381HashOut::<F>::from_bytes(&bytes);
        assert_eq!(hash, hash_from_bytes);
    }

    #[test]
    fn test_serialization() {
        let fr = Fr::from_str_vartime(
            "11575173631114898451293296430061690731976535592475236587664058405912382527658",
        )
        .unwrap();
        let hash = PoseidonBLS12381HashOut::<GoldilocksField> {
            value: fr,
            _phantom: PhantomData,
        };

        let serialized = serde_json::to_string(&hash).unwrap();
        let deserialized: PoseidonBLS12381HashOut<GoldilocksField> =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(hash, deserialized);
    }
}
