use city_crypto::hash::qhashout::QHashOut;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use super::traits::qstandard::QStandardCircuit;
use super::zk_signature::ZKSignatureCircuit;
use crate::builder::verify::CircuitBuilderVerifyProofHelpers;
use crate::proof_minifier::pm_core::get_circuit_fingerprint_generic;

#[derive(Debug)]
pub struct ZKSignatureWrapperCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub verifier_data_target: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for ZKSignatureWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> ZKSignatureWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let child_circuit_data =
            ZKSignatureCircuit::<C, D>::new(QHashOut::from_values(1337, 1337, 1337, 1337));

        let child_common_data = child_circuit_data.get_common_circuit_data_ref();
        let verifier_data_cap_height = child_circuit_data
            .get_verifier_config_ref()
            .constants_sigmas_cap
            .height();
        Self::new_from_common(child_common_data, verifier_data_cap_height)
    }
    pub fn new_from_common(
        child_common_data: &CommonCircuitData<C::F, D>,
        verifier_data_cap_height: usize,
    ) -> Self {
        //let public_key = SimpleL2PrivateKey::new(private_key).get_public_key();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        //let verifier_template = get_verifier_template_zk_signature();

        //let common_proof = verifier_template.get_common_data::<C, D>();

        let verifier_data_target = builder.add_virtual_verifier_data(verifier_data_cap_height);
        let proof_target = builder.add_virtual_proof_with_pis(child_common_data);
        //let proof_target = builder.add_virtual_proof_with_pis_vt(&verifier_template);

        builder.verify_proof::<C>(&proof_target, &verifier_data_target, child_common_data);

        let fingerprint_target =
            builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data_target);
        assert_eq!(
            proof_target.public_inputs.len(),
            4,
            "signature proofs should have 4 public inputs"
        );
        let action_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[0],
                proof_target.public_inputs[1],
                proof_target.public_inputs[2],
                proof_target.public_inputs[3],
            ],
        };
        builder.register_public_inputs(&fingerprint_target.elements);
        builder.register_public_inputs(&action_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            verifier_data_target,
            proof_target,

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
        pw.set_proof_with_pis_target(&self.proof_target, &proof);
        pw.set_verifier_data_target(&self.verifier_data_target, &verifier_data);
        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for ZKSignatureWrapperCircuit<C, D>
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
