use city_common::logging::debug_timer::DebugTimer;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::signature::secp256k1::core::QEDCompressedSecp256K1Signature;
use city_crypto::signature::secp256k1::core::QEDPreparedSecp256K1Signature;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::traits::qstandard::QStandardCircuit;
use crate::crypto::secp256k1::gadget::DogeQEDSignatureGadget;
use crate::proof_minifier::pm_chain::OASProofMinifierChain;

#[derive(Debug)]
pub struct L1Secp256K1SignatureCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub signature_gadget: DogeQEDSignatureGadget,
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: OASProofMinifierChain<D, C::F, C>,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone for L1Secp256K1SignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> L1Secp256K1SignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let signature_gadget =
            DogeQEDSignatureGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);

        builder.register_public_inputs(&signature_gadget.combined_hash.elements);
        let circuit_data = builder.build::<C>();

        let minifier_chain = OASProofMinifierChain::<D, C::F, C>::new(
            &circuit_data.verifier_only,
            &circuit_data.common,
            2,
        );

        Self {
            base_circuit_data: circuit_data,
            signature_gadget,
            minifier_chain,
        }
    }
    pub fn prove(
        &self,
        compressed_signature: &QEDCompressedSecp256K1Signature,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let prepared_signature: QEDPreparedSecp256K1Signature<C::F> =
            compressed_signature.try_into()?;

        let mut timer = DebugTimer::new("DogeSecp256K1SignatureCircuit::Prove");
        timer.lap("start prove base");
        let mut pw = PartialWitness::new();
        self.signature_gadget.set_witness_public_keys_update(
            &mut pw,
            &prepared_signature.public_key,
            &prepared_signature.signature,
            prepared_signature.message,
        );
        let base_proof = self.base_circuit_data.prove(pw)?;
        timer.lap("end prove base");
        timer.lap("start minifier");
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        timer.lap("end minifier");
        Ok(minified_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for L1Secp256K1SignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
