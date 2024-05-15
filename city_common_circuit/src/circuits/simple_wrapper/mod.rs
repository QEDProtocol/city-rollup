use city_crypto::hash::qhashout::QHashOut;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::
    proof_minifier::pm_core::get_circuit_fingerprint_generic
;

use super::traits::qstandard::QStandardCircuit;
#[derive(Debug)]
pub struct SimpleWrapper<C: GenericConfig<D> + 'static, const D: usize>
{
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> SimpleWrapper<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(inner_common_data: &CommonCircuitData<C::F, D>, inner_verifier_data: &VerifierOnlyCircuitData<C, D>) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let proof_target = builder.add_virtual_proof_with_pis(inner_common_data);
        let verifier_data_target = builder.constant_verifier_data(inner_verifier_data);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, &inner_common_data);
        builder.register_public_inputs(&proof_target.public_inputs);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, C::F, C>(&circuit_data.verifier_only));
        Self {
            proof_target,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, proof);
        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for SimpleWrapper<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
      &self.circuit_data.common
    }
}