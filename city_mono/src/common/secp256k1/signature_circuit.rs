use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    common::proof_minifier::pm_chain::OASProofMinifierChain, logging::debug_timer::DebugTimer,
};

use super::{
    ecdsa::curve::{
        ecdsa::{ECDSAPublicKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
    gadget::Secp256K1CircuitGadget,
};

pub struct Secp256K1SignatureCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub signature_gadget: Secp256K1CircuitGadget,
    pub base_circuit_data: CircuitData<F, C, D>,
    pub minifier_chain: OASProofMinifierChain<D, F, C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Secp256K1SignatureCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let signature_gadget =
            Secp256K1CircuitGadget::add_virtual_to::<F, D, C::Hasher>(&mut builder);

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
        msg: &Secp256K1Scalar,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut timer = DebugTimer::new("Secp256K1SignatureCircuit::Prove");
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

    use anyhow::Result;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2::field::types::Sample;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::common::secp256k1::ecdsa::curve::curve_types::{Curve, CurveScalar};
    use crate::common::secp256k1::ecdsa::curve::ecdsa::{
        sign_message, ECDSAPublicKey, ECDSASecretKey,
    };
    use crate::common::secp256k1::ecdsa::curve::secp256k1::Secp256K1;
    use crate::logging::debug_timer::DebugTimer;

    use super::Secp256K1SignatureCircuit;

    fn test_ecdsa_circuit_with_config_v2() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let msg = Secp256K1Scalar::rand();

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);
        let circuit = Secp256K1SignatureCircuit::<F, C, D>::new();
        let proof = circuit.prove(&pk, &sig, &msg)?;
        let common_data = circuit.minifier_chain.get_common_data();
        println!("common_data: {:?}\n", common_data);

        circuit.minifier_chain.verify(proof)
    }

    #[test]
    #[ignore]
    fn prove_ecdsa_circuit() -> Result<()> {
        test_ecdsa_circuit_with_config_v2()
    }
}
