use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    btc::data::rollup::signature::PRIVATE_KEY_CONSTANTS,
    common::{proof_minifier::pm_chain::OASProofMinifierChain, QHashOut},
    logging::debug_timer::DebugTimer,
};

pub struct SimpleL2SignatureCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub private_key: HashOutTarget,
    pub action_hash: HashOutTarget,
    pub base_circuit_data: CircuitData<F, C, D>,
    pub minifier_chain: OASProofMinifierChain<D, F, C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    SimpleL2SignatureCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let private_key = builder.add_virtual_hash();
        let private_key_constants = PRIVATE_KEY_CONSTANTS
            .iter()
            .map(|c| builder.constant(F::from_canonical_u64(*c)))
            .collect::<Vec<_>>();
        let public_key = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
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

        let result_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
            public_key.elements[0],
            public_key.elements[1],
            public_key.elements[2],
            public_key.elements[3],
            action_hash.elements[0],
            action_hash.elements[1],
            action_hash.elements[2],
            action_hash.elements[3],
        ]);

        builder.register_public_inputs(&result_hash.elements);
        let circuit_data = builder.build::<C>();

        let minifier_chain = OASProofMinifierChain::<D, F, C>::new(
            &circuit_data.verifier_only,
            &circuit_data.common,
            2,
        );

        Self {
            base_circuit_data: circuit_data,
            private_key,
            action_hash,
            minifier_chain,
        }
    }
    pub fn prove(
        &self,
        private_key: QHashOut<F>,
        action_hash: QHashOut<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut timer = DebugTimer::new("L2Signature::Prove");
        timer.lap("start prove base");
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.private_key, private_key.0);
        pw.set_hash_target(self.action_hash, action_hash.0);
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
    use plonky2::{
        field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
        plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        btc::{
            circuits::l2_signature::SimpleL2SignatureCircuit,
            data::rollup::{
                constants::NETWORK_MAGIC_DOGE_REGTEST,
                signature::{QEDSigAction, SimpleL2PrivateKey},
            },
        },
        common::QHashOut,
    };

    #[test]
    fn full_signature_flow() {
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        const D: usize = 2;

        let private_key = SimpleL2PrivateKey::new(QHashOut::<F>::rand());
        let action =
            QEDSigAction::<F>::new_transfer_action(NETWORK_MAGIC_DOGE_REGTEST, 0, 1, 2, 1337);
        let public_key = private_key.get_public_key::<PoseidonHash>();
        let action_hash = QHashOut(action.get_hash::<PoseidonHash>());

        let simple_l2_sig_circuit = SimpleL2SignatureCircuit::<F, C, D>::new();
        let proof = simple_l2_sig_circuit
            .prove(private_key.private_key, action_hash)
            .unwrap();
        simple_l2_sig_circuit.minifier_chain.verify(proof).unwrap();
    }
}
