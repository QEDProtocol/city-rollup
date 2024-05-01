use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};

use crate::common::{hash::traits::hasher::QHasher, QHashOut};

impl<F: RichField> QHasher<F> for PoseidonHash {
    fn q_two_to_one(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
        QHashOut(Self::two_to_one(left.0, right.0))
    }
}

const fn gl_hash_out_from_u64(a: u64, b: u64, c: u64, d: u64) -> HashOut<GoldilocksField> {
    HashOut {
        elements: [
            GoldilocksField(a),
            GoldilocksField(b),
            GoldilocksField(c),
            GoldilocksField(d),
        ],
    }
}
pub const POSEDION_GOLDILOCKS_ZERO_HASHES: [HashOut<GoldilocksField>; 1] =
    [gl_hash_out_from_u64(0, 0, 0, 0)];
