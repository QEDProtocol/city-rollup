pub mod fixed_public_key;
pub mod inner;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::hash::traits::hasher::MerkleZeroHasher;
use city_rollup_common::introspection::rollup::signature::SimpleL2PrivateKey;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::Deserialize;
use serde::Serialize;

use self::fixed_public_key::ZKSignatureCircuitSimpleFixedPublicKey;
use self::inner::ZKSignatureCircuitInner;
use super::traits::qstandard::provable::QStandardCircuitProvable;
use super::traits::qstandard::QStandardCircuit;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct ZKSignatureCircuitInput<F: RichField> {
    pub private_key: QHashOut<F>,
    pub action_hash: QHashOut<F>,
}

#[derive(Debug)]
pub struct ZKSignatureCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub inner_circuit: ZKSignatureCircuitInner<C, D>,
    pub fixed_circuit: ZKSignatureCircuitSimpleFixedPublicKey<C, D>,
    pub hash_public_key: QHashOut<C::F>,
    pub circuit_fingerprint_public_key: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for ZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        let inner_clone = self.inner_circuit.clone();
        let wrapper_clone = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(
            &inner_clone,
            self.hash_public_key,
        );
        Self {
            inner_circuit: inner_clone,
            fixed_circuit: wrapper_clone,
            hash_public_key: self.hash_public_key,
            circuit_fingerprint_public_key: self.circuit_fingerprint_public_key,
        }
    }
}
impl<C: GenericConfig<D>, const D: usize> ZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(public_key: QHashOut<C::F>) -> Self {
        let inner_circuit = ZKSignatureCircuitInner::<C, D>::new();
        let fixed_circuit =
            ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(&inner_circuit, public_key);

        let hash_public_key = public_key;
        let circuit_fingerprint_public_key = fixed_circuit.get_fingerprint();
        Self {
            inner_circuit,
            fixed_circuit,
            hash_public_key,
            circuit_fingerprint_public_key,
        }
    }
    pub fn prove_base(
        &self,
        private_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let inner_proof = self.inner_circuit.prove_base(private_key, action_hash)?;

        self.fixed_circuit.prove_base(&inner_proof)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for ZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fixed_circuit.get_fingerprint()
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.fixed_circuit.get_verifier_config_ref()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.fixed_circuit.get_common_circuit_data_ref()
    }
}
impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<ZKSignatureCircuitInput<C::F>, C, D> for ZKSignatureCircuit<C, D>
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

pub fn gen_standard_wrapped_zk_signature_proof<C: GenericConfig<D> + 'static, const D: usize>(
    private_key: QHashOut<C::F>,
    action_hash: QHashOut<C::F>,
) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    let public_key = SimpleL2PrivateKey::new(private_key).get_public_key::<C::Hasher>();
    let sig_circuit = ZKSignatureCircuit::<C, D>::new(public_key);
    sig_circuit.prove_base(private_key, action_hash)
}

pub fn verify_standard_wrapped_zk_signature_proof<C: GenericConfig<D> + 'static, const D: usize>(
    public_key: QHashOut<C::F>,
    signature_proof: Vec<u8>,
) -> anyhow::Result<()>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    let circuit = ZKSignatureCircuit::<C, D>::new(public_key);
    let proof = ProofWithPublicInputs::<C::F, C, D>::from_bytes(
        signature_proof,
        circuit.get_common_circuit_data_ref(),
    )?;
    let verifier = VerifierCircuitData {
        verifier_only: circuit.get_verifier_config_ref().clone(),
        common: circuit.get_common_circuit_data_ref().clone(),
    };
    verifier.verify(proof)?;

    Ok(())
}
