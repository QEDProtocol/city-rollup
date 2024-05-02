use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::field::qfield::QRichField;
use crate::hash::qhashout::QHashOut;

pub trait QHasher<F: RichField> {
    fn q_two_to_one(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F>;
}
pub trait ZeroableHash: Sized + Copy + Clone {
    fn get_zero_value() -> Self;
}
impl<F: Field> ZeroableHash for HashOut<F> {
    fn get_zero_value() -> Self {
        HashOut::<F>::ZERO
    }
}
impl<F: Field> ZeroableHash for QHashOut<F> {
    fn get_zero_value() -> Self {
        QHashOut(HashOut::<F>::ZERO)
    }
}
pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(left: &Hash, right: &Hash) -> Hash;
}
pub trait MerkleHasherWithMarkedLeaf<Hash: PartialEq>: MerkleHasher<Hash> {
    fn two_to_one_marked_leaf(left: &Hash, right: &Hash) -> Hash;
}

pub trait MerkleZeroHasher<Hash: PartialEq>: MerkleHasher<Hash> {
    fn get_zero_hash(reverse_level: usize) -> Hash;
}
pub trait BaseMerkleZeroHasherWithMarkedLeaf<Hash: PartialEq>:
    MerkleHasherWithMarkedLeaf<Hash>
{
    fn get_zero_hash_marked(reverse_level: usize) -> Hash;
}
pub trait MerkleZeroHasherWithMarkedLeaf<Hash: PartialEq>:
    BaseMerkleZeroHasherWithMarkedLeaf<Hash> + MerkleZeroHasher<Hash>
{
}

pub const ZERO_HASH_CACHE_SIZE: usize = 128;
pub trait MerkleZeroHasherWithCache<Hash: PartialEq + Copy>: MerkleHasher<Hash> {
    const CACHED_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
}
pub trait MerkleZeroHasherWithCacheMarkedLeaf<Hash: PartialEq + Copy>:
    MerkleHasherWithMarkedLeaf<Hash>
{
    const CACHED_MARKED_LEAF_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
}

pub trait FieldHasher<Hash, F: RichField> {
    fn hash_many(elements: &[F]) -> Hash;
    fn hash_many_pad(elements: &[F]) -> Hash;
}

pub trait FieldQHasher<F: RichField> {
    fn w_hash_many(elements: &[F]) -> QHashOut<F>;
    fn w_hash_many_pad(elements: &[F]) -> QHashOut<F>;
}
impl<F: RichField, FH: FieldHasher<HashOut<F>, F>> FieldQHasher<F> for FH {
    fn w_hash_many(elements: &[F]) -> QHashOut<F> {
        QHashOut(FH::hash_many(elements))
    }

    fn w_hash_many_pad(elements: &[F]) -> QHashOut<F> {
        QHashOut(FH::hash_many_pad(elements))
    }
}
pub struct PoseidonHasher;

impl<F: QRichField> MerkleHasher<HashOut<F>> for PoseidonHasher {
    fn two_to_one(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        <PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(*left, *right)
    }
}
impl<F: QRichField> MerkleHasherWithMarkedLeaf<HashOut<F>> for PoseidonHasher {
    fn two_to_one_marked_leaf(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        PoseidonHash::hash_no_pad(&[
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
            F::ONE,
        ])
    }
}

impl<F: QRichField> MerkleHasher<QHashOut<F>> for PoseidonHasher {
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(<PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(left.0, right.0))
    }
}
impl<F: QRichField> MerkleHasherWithMarkedLeaf<QHashOut<F>> for PoseidonHasher {
    fn two_to_one_marked_leaf(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(PoseidonHash::hash_no_pad(&[
            left.0.elements[0],
            left.0.elements[1],
            left.0.elements[2],
            left.0.elements[3],
            right.0.elements[0],
            right.0.elements[1],
            right.0.elements[2],
            right.0.elements[3],
            F::ONE,
        ]))
    }
}

impl<F: QRichField> MerkleHasherWithMarkedLeaf<QHashOut<F>> for PoseidonHash {
    fn two_to_one_marked_leaf(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(PoseidonHash::hash_no_pad(&[
            left.0.elements[0],
            left.0.elements[1],
            left.0.elements[2],
            left.0.elements[3],
            right.0.elements[0],
            right.0.elements[1],
            right.0.elements[2],
            right.0.elements[3],
            F::ONE,
        ]))
    }
}
impl<F: QRichField> MerkleHasherWithMarkedLeaf<HashOut<F>> for PoseidonHash {
    fn two_to_one_marked_leaf(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        PoseidonHash::hash_no_pad(&[
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
            F::ONE,
        ])
    }
}

impl<F: QRichField> MerkleHasher<QHashOut<F>> for PoseidonHash {
    fn two_to_one(left: &QHashOut<F>, right: &QHashOut<F>) -> QHashOut<F> {
        QHashOut(<PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(left.0, right.0))
    }
}
impl<F: QRichField> MerkleHasher<HashOut<F>> for PoseidonHash {
    fn two_to_one(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
        <PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(*left, *right)
    }
}

impl BaseMerkleZeroHasherWithMarkedLeaf<QHashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash_marked(reverse_level: usize) -> QHashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash_marked(reverse_level)
    }
}
impl MerkleZeroHasher<QHashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash(reverse_level: usize) -> QHashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash(reverse_level)
    }
}

impl BaseMerkleZeroHasherWithMarkedLeaf<HashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash_marked(reverse_level: usize) -> HashOut<GoldilocksField> {
        <PoseidonHash as BaseMerkleZeroHasherWithMarkedLeaf<QHashOut<GoldilocksField>>>::get_zero_hash_marked(reverse_level).0
    }
}
impl MerkleZeroHasher<HashOut<GoldilocksField>> for PoseidonHash {
    fn get_zero_hash(reverse_level: usize) -> HashOut<GoldilocksField> {
        PoseidonHasher::get_zero_hash(reverse_level)
    }
}

/*
fn compute_zero_hashes_core<Hash: PartialEq + ZeroableHash + Copy, Hasher: MerkleHasher<Hash>, const N: usize>() -> [Hash; N] {
    let mut result = [Hash::get_zero_value(); N];

    for i in 1..N {
        result[i] = Hasher::two_to_one(&result[i-1], &result[i-1]);
    }
    result
}*/
impl<F: RichField, H: Hasher<F, Hash = HashOut<F>>> FieldHasher<HashOut<F>, F> for H {
    fn hash_many(elements: &[F]) -> HashOut<F> {
        H::hash_no_pad(elements)
    }

    fn hash_many_pad(elements: &[F]) -> HashOut<F> {
        H::hash_pad(elements)
    }
}

fn iterate_merkle_hasher<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    mut current: Hash,
    reverse_level: usize,
) -> Hash {
    for _ in 0..reverse_level {
        current = Hasher::two_to_one(&current, &current);
    }
    current
}
impl<Hash: PartialEq + Copy, T: MerkleZeroHasherWithCache<Hash>> MerkleZeroHasher<Hash> for T {
    fn get_zero_hash(reverse_level: usize) -> Hash {
        if reverse_level < ZERO_HASH_CACHE_SIZE {
            T::CACHED_ZERO_HASHES[reverse_level]
        } else {
            let current = T::CACHED_ZERO_HASHES[ZERO_HASH_CACHE_SIZE - 1];
            iterate_merkle_hasher::<Hash, Self>(current, reverse_level - ZERO_HASH_CACHE_SIZE + 1)
        }
    }
}

impl<Hash: PartialEq + Copy, T: MerkleZeroHasherWithCacheMarkedLeaf<Hash>>
    BaseMerkleZeroHasherWithMarkedLeaf<Hash> for T
{
    fn get_zero_hash_marked(reverse_level: usize) -> Hash {
        if reverse_level < ZERO_HASH_CACHE_SIZE {
            T::CACHED_MARKED_LEAF_ZERO_HASHES[reverse_level]
        } else {
            let current = T::CACHED_MARKED_LEAF_ZERO_HASHES[ZERO_HASH_CACHE_SIZE - 1];
            iterate_merkle_hasher::<Hash, Self>(current, reverse_level - ZERO_HASH_CACHE_SIZE + 1)
        }
    }
}

impl<
        Hash: PartialEq + Copy,
        T: MerkleZeroHasherWithCacheMarkedLeaf<Hash> + MerkleZeroHasherWithCache<Hash>,
    > MerkleZeroHasherWithMarkedLeaf<Hash> for T
{
}
