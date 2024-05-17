use city_common_circuit::{
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit},
    proof_minifier::pm_chain::OASProofMinifierChain,
};
use city_crypto::hash::{qhashout::QHashOut, traits::hasher::MerkleZeroHasher};
use city_rollup_common::introspection::rollup::signature::PRIVATE_KEY_CONSTANTS;
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRL2SignatureCircuitInput<F: RichField> {
    pub private_key: QHashOut<F>,
    pub action_hash: QHashOut<F>,
}

#[derive(Debug)]
pub struct CRL2SignatureCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub private_key: HashOutTarget,
    pub action_hash: HashOutTarget,
    // end circuit targets
    pub minifier_chain: OASProofMinifierDynamicChain<D, C::F, C>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub public_key: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for CRL2SignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new(self.public_key)
    }
}
impl<C: GenericConfig<D>, const D: usize> CRL2SignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(public_key: QHashOut<C::F>) -> Self {
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
        let public_key_expected = builder.constant_hash(public_key.0);
        builder.connect_hashes(public_key_target, public_key_expected);

        let action_hash = builder.add_virtual_hash();

        builder.register_public_inputs(&action_hash.elements);
        let circuit_data = builder.build::<C>();

        let minifier_chain = OASProofMinifierDynamicChain::<D, C::F, C>::new(
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

            public_key,
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
        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for CRL2SignatureCircuit<C, D>
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
    QStandardCircuitProvable<CRL2SignatureCircuitInput<C::F>, C, D> for CRL2SignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &CRL2SignatureCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input.private_key, input.action_hash)
    }
}
