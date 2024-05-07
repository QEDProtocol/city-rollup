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
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    proof_minifier::{pm_chain::OASProofMinifierChain, pm_core::get_circuit_fingerprint_generic},
    verify_template::{
        circuit_template::QEDCircuitVerifyTemplate,
        ser_data::{VTFriConfig, VTFriParams, VTFriReductionStrategy},
    },
};

use super::{
    super::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit},
    ZKSignatureCircuitInput,
};
#[derive(Debug)]
pub struct ZKSignatureCircuitInner<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub private_key: HashOutTarget,
    pub action_hash: HashOutTarget,
    // end circuit targets
    pub minifier_chain: OASProofMinifierChain<D, C::F, C>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for ZKSignatureCircuitInner<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> ZKSignatureCircuitInner<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        //let public_key = SimpleL2PrivateKey::new(private_key).get_public_key();

        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let private_key = builder.add_virtual_hash();
        let private_key_constants = PRIVATE_KEY_CONSTANTS
            .iter()
            .map(|c| builder.constant(C::F::from_canonical_u64(*c)))
            .collect::<Vec<_>>();
        let public_key_target = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
            private_key_constants[0],
            private_key_constants[1],
            private_key_constants[2],
            private_key_constants[19],
            private_key.elements[1],
            private_key_constants[1],
            private_key_constants[2],
            private_key_constants[3],
            private_key_constants[4],
            private_key_constants[5],
            private_key_constants[6],
            private_key.elements[0],
            private_key_constants[7],
            private_key.elements[2],
            private_key_constants[8],
            private_key_constants[9],
            private_key_constants[10],
            private_key_constants[11],
            private_key_constants[12],
            private_key.elements[3],
            private_key_constants[13],
            private_key_constants[14],
            private_key_constants[15],
            private_key_constants[16],
            private_key_constants[17],
            private_key_constants[18],
        ]);

        let action_hash = builder.add_virtual_hash();
        let combined_hash = builder.hash_two_to_one::<C::Hasher>(public_key_target, action_hash);

        builder.register_public_inputs(&action_hash.elements);
        builder.register_public_inputs(&combined_hash.elements);
        let circuit_data = builder.build::<C>();

        let minifier_chain = OASProofMinifierChain::<D, C::F, C>::new(
            &circuit_data.verifier_only,
            &circuit_data.common,
            2,
        );
        let fingerprint = QHashOut(minifier_chain.get_fingerprint());
        Self {
            private_key,
            action_hash,
            circuit_data,
            minifier_chain: minifier_chain,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        private_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.private_key, private_key.0);
        pw.set_hash_target(self.action_hash, action_hash.0);
        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier_chain.prove(&inner_proof)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for ZKSignatureCircuitInner<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<ZKSignatureCircuitInput<C::F>, C, D> for ZKSignatureCircuitInner<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &ZKSignatureCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input.private_key, input.action_hash)
    }
}
