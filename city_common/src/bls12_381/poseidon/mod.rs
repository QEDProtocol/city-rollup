pub mod constants;

use std::ops::AddAssign;
use std::ops::MulAssign;

use ff::Field;

use crate::bls12_381::fr::Fr;
use crate::bls12_381::poseidon::constants::C_CONSTANTS;
use crate::bls12_381::poseidon::constants::M_MATRIX;
use crate::bls12_381::poseidon::constants::P_MATRIX;
use crate::bls12_381::poseidon::constants::S_CONSTANTS;

pub const RATE: usize = 3;
pub const WIDTH: usize = 4;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;
pub const GOLDILOCKS_ELEMENTS: usize = 3;

pub type PoseidonState = [Fr; WIDTH];

// This poseidon BN128 implementation is based on the following implementation:
// https://github.com/iden3/go-iden3-crypto/blob/e5cf066b8be3da9a3df9544c65818df189fdbebe/poseidon/poseidon.go
pub fn permution(state: &mut PoseidonState) {
    ark(state, 0);
    full_rounds(state, true);
    partial_rounds(state);
    full_rounds(state, false);
}

fn ark(state: &mut PoseidonState, it: usize) {
    for i in 0..WIDTH {
        state[i].add_assign(&C_CONSTANTS[it + i]);
    }
}

fn exp5(mut x: Fr) -> Fr {
    let aux = x;
    x = x.square();
    x = x.square();
    x.mul_assign(&aux);

    x
}

fn exp5_state(state: &mut PoseidonState) {
    for state_element in state.iter_mut().take(WIDTH) {
        *state_element = exp5(*state_element);
    }
}

fn full_rounds(state: &mut PoseidonState, first: bool) {
    for i in 0..FULL_ROUNDS / 2 - 1 {
        exp5_state(state);
        if first {
            ark(state, (i + 1) * WIDTH);
        } else {
            ark(
                state,
                (FULL_ROUNDS / 2 + 1) * WIDTH + PARTIAL_ROUNDS + i * WIDTH,
            );
        }
        mix(state, &M_MATRIX);
    }

    exp5_state(state);
    if first {
        ark(state, (FULL_ROUNDS / 2) * WIDTH);
        mix(state, &P_MATRIX);
    } else {
        mix(state, &M_MATRIX);
    }
}

fn partial_rounds(state: &mut PoseidonState) {
    for i in 0..PARTIAL_ROUNDS {
        state[0] = exp5(state[0]);
        state[0].add_assign(&C_CONSTANTS[(FULL_ROUNDS / 2 + 1) * WIDTH + i]);

        let mut mul;
        let mut new_state0 = Fr::ZERO;
        for j in 0..WIDTH {
            mul = Fr::ZERO;
            mul.add_assign(&S_CONSTANTS[(WIDTH * 2 - 1) * i + j]);
            mul.mul_assign(&state[j]);
            new_state0.add_assign(&mul);
        }

        for k in 1..WIDTH {
            mul = Fr::ZERO;
            mul.add_assign(&state[0]);
            mul.mul_assign(&S_CONSTANTS[(WIDTH * 2 - 1) * i + WIDTH + k - 1]);
            state[k].add_assign(&mul);
        }

        state[0] = new_state0;
    }
}

fn mix(state: &mut PoseidonState, constant_matrix: &[Vec<Fr>]) {
    let mut result: PoseidonState = [Fr::ZERO; WIDTH];

    let mut mul;
    for (i, result_element) in result.iter_mut().enumerate().take(WIDTH) {
        for j in 0..WIDTH {
            mul = Fr::ZERO;
            mul.add_assign(&constant_matrix[j][i]);
            mul.mul_assign(&state[j]);
            result_element.add_assign(&mul);
        }
    }

    state[..WIDTH].copy_from_slice(&result[..WIDTH]);
}

#[cfg(test)]
mod merkle_tree_tests {
    use anyhow::Result;
    use plonky2::field::extension::Extendable;
    use plonky2::hash::hash_types::RichField;
    use plonky2::hash::merkle_proofs::verify_merkle_proof_to_cap;
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::plonk::config::GenericConfig;

    use crate::bls12_381::plonky2_config::PoseidonBLS12381GoldilocksConfig;

    fn random_data<F: RichField>(n: usize, k: usize) -> Vec<Vec<F>> {
        (0..n).map(|_| F::rand_vec(k)).collect()
    }

    fn verify_all_leaves<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        leaves: Vec<Vec<F>>,
        cap_height: usize,
    ) -> Result<()> {
        let tree = MerkleTree::<F, C::Hasher>::new(leaves.clone(), cap_height);
        for (i, leaf) in leaves.into_iter().enumerate() {
            let proof = tree.prove(i);
            verify_merkle_proof_to_cap(leaf, i, &tree.cap, &proof)?;
        }
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_cap_height_too_big() {
        const D: usize = 2;
        type C = PoseidonBLS12381GoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let log_n = 8;
        let cap_height = log_n + 1; // Should panic if `cap_height > len_n`.

        let leaves = random_data::<F>(1 << log_n, 7);
        let _ = MerkleTree::<F, <C as GenericConfig<D>>::Hasher>::new(leaves, cap_height);
    }

    #[test]
    fn test_cap_height_eq_log2_len() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonBLS12381GoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let log_n = 8;
        let n = 1 << log_n;
        let leaves = random_data::<F>(n, 7);

        verify_all_leaves::<F, C, D>(leaves, log_n)?;

        Ok(())
    }

    #[test]
    fn test_merkle_trees() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonBLS12381GoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let log_n = 8;
        let n = 1 << log_n;
        let leaves = random_data::<F>(n, 7);

        verify_all_leaves::<F, C, D>(leaves, 1)?;

        Ok(())
    }
}
