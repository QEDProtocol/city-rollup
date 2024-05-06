use city_crypto::hash::{qhashout::QHashOut, traits::hasher::MerkleZeroHasher};
use city_rollup_common::introspection::rollup::signature::{
    SimpleL2PrivateKey, PRIVATE_KEY_CONSTANTS,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit},
    proof_minifier::{pm_chain::OASProofMinifierChain, pm_core::get_circuit_fingerprint_generic},
    verify_template::{
        circuit_template::QEDCircuitVerifyTemplate,
        ser_data::{VTFriConfig, VTFriParams, VTFriReductionStrategy},
    },
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct ZKSignatureCircuitInput<F: RichField> {
    pub private_key: QHashOut<F>,
    pub action_hash: QHashOut<F>,
}

#[derive(Debug)]
pub struct ZKSignatureCircuitSimpleFixedPublicKey<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub public_key: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> ZKSignatureCircuitSimpleFixedPublicKey<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_from_isc<ISC: QStandardCircuit<C, D>>(
        inner_sig_circuit: &ISC,
        public_key: QHashOut<C::F>,
    ) -> Self {
        Self::new(
            inner_sig_circuit.get_common_circuit_data_ref(),
            inner_sig_circuit.get_verifier_config_ref(),
            public_key,
        )
    }
    pub fn new(
        inner_sig_circuit_common: &CommonCircuitData<C::F, D>,
        inner_sig_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        public_key: QHashOut<C::F>,
    ) -> Self {
        //let public_key = SimpleL2PrivateKey::new(private_key).get_public_key();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let proof_target = builder.add_virtual_proof_with_pis(inner_sig_circuit_common);
        let verifier_data = builder.constant_verifier_data(inner_sig_circuit_verifier_data);
        builder.verify_proof::<C>(&proof_target, &verifier_data, inner_sig_circuit_common);

        let public_key_target = builder.constant_hash(public_key.0);
        let action_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[0],
                proof_target.public_inputs[1],
                proof_target.public_inputs[2],
                proof_target.public_inputs[3],
            ],
        };
        let expected_combined_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[4],
                proof_target.public_inputs[5],
                proof_target.public_inputs[6],
                proof_target.public_inputs[7],
            ],
        };

        let combined_hash = builder.hash_two_to_one::<C::Hasher>(public_key_target, action_hash);

        builder.connect_hashes(combined_hash, expected_combined_hash);

        builder.register_public_inputs(&action_hash.elements);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            proof_target,
            circuit_data,
            public_key,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        inner_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, inner_proof);
        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for ZKSignatureCircuitSimpleFixedPublicKey<C, D>
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
impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<ProofWithPublicInputs<C::F, C, D>, C, D>
    for ZKSignatureCircuitSimpleFixedPublicKey<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}
