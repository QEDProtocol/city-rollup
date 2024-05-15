use city_crypto::hash::qhashout::QHashOut;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers}, 
    proof_minifier::pm_core::get_circuit_fingerprint_generic}
;

use super::super::traits::qstandard::QStandardCircuit;
#[derive(Debug)]
pub struct SimpleWrapperDynamic<C: GenericConfig<D> + 'static, const D: usize>
where C::Hasher: AlgebraicHasher<C::F>
{
  pub proof_target: ProofWithPublicInputsTarget<D>,
  pub verifier_data_target: VerifierCircuitTarget,
  pub circuit_data: CircuitData<C::F, C, D>,
  pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> SimpleWrapperDynamic<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(inner_common_data: &CommonCircuitData<C::F, D>, inner_fingerprint: QHashOut<C::F>, inner_verifier_data_cap_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        
        let proof_target = builder.add_virtual_proof_with_pis(inner_common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, &inner_common_data);
        
        let expected_fingerprint = builder.constant_whash(inner_fingerprint);
        let actual_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);
        builder.register_public_inputs(&proof_target.public_inputs);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, C::F, C>(&circuit_data.verifier_only));
        Self {
            proof_target,
            verifier_data_target,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        proof: &ProofWithPublicInputs<C::F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, proof);
        pw.set_verifier_data_target(&self.verifier_data_target, verifier_data);
        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for SimpleWrapperDynamic<C, D>
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