use crate::common::QHashOut;
use plonky2::plonk::config::Hasher;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::{
        hash_types::{HashOut, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
    },
};

pub fn get_circuit_fingerprint_generic<
    const D: usize,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
>(
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> HashOut<F>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut all: Vec<F> = vec![];
    for sc in verifier_data.constants_sigmas_cap.0.iter() {
        all.push(sc.elements[0]);
        all.push(sc.elements[1]);
        all.push(sc.elements[2]);
        all.push(sc.elements[3]);
    }
    all.push(verifier_data.circuit_digest.elements[0]);
    all.push(verifier_data.circuit_digest.elements[1]);
    all.push(verifier_data.circuit_digest.elements[2]);
    all.push(verifier_data.circuit_digest.elements[3]);

    let output = C::Hasher::hash_no_pad(&all);
    output
}

pub fn get_circuit_fingerprint_poseidon_goldilocks(
    verifier_data: &VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>,
) -> HashOut<GoldilocksField> {
    let all_components: Vec<GoldilocksField> = verifier_data
        .constants_sigmas_cap
        .0
        .iter()
        .flat_map(|f| f.elements)
        .chain(verifier_data.circuit_digest.elements)
        .collect();
    let output = hash_n_to_hash_no_pad::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(
        &all_components,
    );
    output
}

pub fn get_w_circuit_fingerprint_poseidon_goldilocks(
    verifier_data: &VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>,
) -> QHashOut<GoldilocksField> {
    QHashOut(get_circuit_fingerprint_poseidon_goldilocks(verifier_data))
}
#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        hash::poseidon::PoseidonHash,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::common::verify::fingerprint::get_w_circuit_fingerprint_poseidon_goldilocks;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    pub fn compute_circuit_fingerprint_poseidon_goldilocks() {
        type H = PoseidonHash;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_target = builder.add_virtual_target();
        let public_hash_target =
            builder.hash_n_to_hash_no_pad::<H>(vec![a_target, a_target, a_target, a_target]);
        builder.register_public_inputs(&public_hash_target.elements);

        let data = builder.build::<C>();

        let w_fingerprint =
            get_w_circuit_fingerprint_poseidon_goldilocks(&data.verifier_only).to_string();
        assert_eq!(
            w_fingerprint,
            "1cda093d8ad955a582c3c08d2feab763907835305c1e29d0ab6dd23dca9fba44"
        );
    }
}
