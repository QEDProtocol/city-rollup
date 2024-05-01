use plonky2::hash::hash_types::RichField;

use crate::common::{hash::traits::hasher::QHasher, QHashOut};

pub fn compute_zero_hashes<F: RichField, H: QHasher<F>>(height: u8) -> Vec<QHashOut<F>> {
    let mut zero_hashes = vec![QHashOut::<F>::ZERO];
    let mut current = QHashOut::<F>::ZERO;
    for _ in 0..height {
        current = H::q_two_to_one(current, current);
        zero_hashes.push(current);
    }
    zero_hashes
}
