use city_common::logging::debug_timer::DebugTimer;
use city_crypto::{
    hash::qhashout::QHashOut,
    signature::secp256k1::core::{QEDCompressedSecp256K1Signature, QEDPreparedSecp256K1Signature},
};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    crypto::secp256k1::gadget::DogeQEDSignatureGadget,
    proof_minifier::pm_chain_dynamic::QEDProofMinifierDynamicChain,
};

use super::traits::qstandard::QStandardCircuit;

#[derive(Debug)]
pub struct L1Secp256K1SignatureCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub signature_gadget: DogeQEDSignatureGadget,
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: QEDProofMinifierDynamicChain<D, C::F, C>,
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

        let minifier_chain =
            QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                &circuit_data.verifier_only,
                &circuit_data.common,
                &[true, false],
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
