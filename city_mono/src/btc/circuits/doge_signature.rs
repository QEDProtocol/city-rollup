use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    common::{
        proof_minifier::pm_chain::OASProofMinifierChain,
        secp256k1::{
            ecdsa::curve::{
                ecdsa::{ECDSAPublicKey, ECDSASignature},
                secp256k1::Secp256K1,
            },
            gadget::DogeQEDSignatureGadget,
        },
    },
    logging::debug_timer::DebugTimer,
};

pub struct DogeSecp256K1SignatureCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub signature_gadget: DogeQEDSignatureGadget,
    pub base_circuit_data: CircuitData<F, C, D>,
    pub minifier_chain: OASProofMinifierChain<D, F, C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    DogeSecp256K1SignatureCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let signature_gadget =
            DogeQEDSignatureGadget::add_virtual_to::<C::Hasher, F, D>(&mut builder);

        builder.register_public_inputs(&signature_gadget.combined_hash.elements);
        let circuit_data = builder.build::<C>();

        let minifier_chain = OASProofMinifierChain::<D, F, C>::new(
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
        public_key: &ECDSAPublicKey<Secp256K1>,
        signature: &ECDSASignature<Secp256K1>,
        msg: HashOut<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut timer = DebugTimer::new("DogeSecp256K1SignatureCircuit::Prove");
        timer.lap("start prove base");
        let mut pw = PartialWitness::new();
        self.signature_gadget
            .set_witness_public_keys_update(&mut pw, public_key, signature, msg);
        let base_proof = self.base_circuit_data.prove(pw)?;
        timer.lap("end prove base");
        timer.lap("start minifier");
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        timer.lap("end minifier");
        Ok(minified_proof)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn full_signature_flow() {}
}
