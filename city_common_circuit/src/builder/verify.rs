use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use super::connect::CircuitBuilderConnectHelpers;

pub trait CircuitBuilderVerifyProofHelpers<F: RichField + Extendable<D>, const D: usize> {
    fn get_circuit_fingerprint<H: AlgebraicHasher<F>>(
        &mut self,
        verifier_data: &VerifierCircuitTarget,
    ) -> HashOutTarget;
    fn verify_proof_with_fingerprint<C: GenericConfig<D, F = F>>(
        &mut self,
        proof_with_pis: &ProofWithPublicInputsTarget<D>,
        inner_verifier_data: &VerifierCircuitTarget,
        inner_common_data: &CommonCircuitData<F, D>,
        fingerprint: HashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    fn verify_proof_with_fingerprint_enum<C: GenericConfig<D, F = F>>(
        &mut self,
        proof_with_pis: &ProofWithPublicInputsTarget<D>,
        inner_verifier_data: &VerifierCircuitTarget,
        inner_common_data: &CommonCircuitData<F, D>,
        allowed_fingerprints: &[HashOutTarget],
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderVerifyProofHelpers<F, D>
    for CircuitBuilder<F, D>
{
    fn get_circuit_fingerprint<H: AlgebraicHasher<F>>(
        &mut self,
        verifier_data: &VerifierCircuitTarget,
    ) -> HashOutTarget {
        let all_contents = verifier_data
            .constants_sigmas_cap
            .0
            .iter()
            .flat_map(|f| f.elements)
            .chain(verifier_data.circuit_digest.elements)
            .collect();
        self.hash_n_to_hash_no_pad::<H>(all_contents)
    }

    fn verify_proof_with_fingerprint<C: GenericConfig<D, F = F>>(
        &mut self,
        proof_with_pis: &ProofWithPublicInputsTarget<D>,
        inner_verifier_data: &VerifierCircuitTarget,
        inner_common_data: &CommonCircuitData<F, D>,
        fingerprint: HashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let calculated_fingerprint = self.get_circuit_fingerprint::<C::Hasher>(inner_verifier_data);
        self.connect_hashes(calculated_fingerprint, fingerprint);
        self.verify_proof::<C>(proof_with_pis, inner_verifier_data, inner_common_data);
    }
    fn verify_proof_with_fingerprint_enum<C: GenericConfig<D, F = F>>(
        &mut self,
        proof_with_pis: &ProofWithPublicInputsTarget<D>,
        inner_verifier_data: &VerifierCircuitTarget,
        inner_common_data: &CommonCircuitData<F, D>,
        allowed_fingerprints: &[HashOutTarget],
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let calculated_fingerprint: HashOutTarget =
            self.get_circuit_fingerprint::<C::Hasher>(inner_verifier_data);
        self.connect_hashes_enum(calculated_fingerprint, allowed_fingerprints);
        self.verify_proof::<C>(proof_with_pis, inner_verifier_data, inner_common_data);
    }
}
