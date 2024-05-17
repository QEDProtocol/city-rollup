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
    proof_minifier::pm_chain::OASProofMinifierChain,
    verify_template::{
        circuit_template::QEDCircuitVerifyTemplate,
        ser_data::{VTFriConfig, VTFriParams, VTFriReductionStrategy},
    },
};

use super::{
    traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit},
    zk_signature_wrapper::ZKSignatureWrapperCircuit,
};

pub fn get_verifier_template_zk_signature() -> QEDCircuitVerifyTemplate {
    QEDCircuitVerifyTemplate {
        verifier_data_cap_height: 4,
        fri_cap_height: 4,
        num_public_inputs: 4,
        num_leaves_per_oracle: vec![85, 135, 20, 16],
        vt_fri_params: VTFriParams {
            config: VTFriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: VTFriReductionStrategy::ConstantArityBits(4, 5),
                num_query_rounds: 28,
            },
            hiding: false,
            degree_bits: 12,
            reduction_arity_bits: vec![4, 4],
        },
        num_challenges: 2,
        total_partial_products: 18,
        num_lookups: 0,
        num_constants: 5,
        num_routed_wires: 80,
        num_wires: 135,
        num_quotient_polys: 16,
        quotient_degree_factor: 8,
        num_gate_constraints: 123,
        k_is: vec![
            1,
            7,
            49,
            343,
            2401,
            16807,
            117649,
            823543,
            5764801,
            40353607,
            282475249,
            1977326743,
            13841287201,
            96889010407,
            678223072849,
            4747561509943,
            33232930569601,
            232630513987207,
            1628413597910449,
            11398895185373143,
            79792266297612001,
            558545864083284007,
            3909821048582988049,
            8922003270666332022,
            7113790686420571191,
            12903046666114829695,
            16534350385145470581,
            5059988279530788141,
            16973173887300932666,
            8131752794619022736,
            1582037354089406189,
            11074261478625843323,
            3732854072722565977,
            7683234439643377518,
            16889152938674473984,
            7543606154233811962,
            15911754940807515092,
            701820169165099718,
            4912741184155698026,
            15942444219675301861,
            916645121239607101,
            6416515848677249707,
            8022122801911579307,
            814627405137302186,
            5702391835961115302,
            3023254712898638472,
            2716038920875884983,
            565528376716610560,
            3958698637016273920,
            9264146389699333119,
            9508792519651578870,
            11221315429317299127,
            4762231727562756605,
            14888878023524711914,
            11988425817600061793,
            10132004445542095267,
            15583798910550913906,
            16852872026783475737,
            7289639770996824233,
            14133990258148600989,
            6704211459967285318,
            10035992080941828584,
            14911712358349047125,
            12148266161370408270,
            11250886851934520606,
            4969231685883306958,
            16337877731768564385,
            3684679705892444769,
            7346013871832529062,
            14528608963998534792,
            9466542400916821939,
            10925564598174000610,
            2691975909559666986,
            397087297503084581,
            2779611082521592067,
            1010533508236560148,
            7073734557655921036,
            12622653764762278610,
            14571600075677612986,
            9767480182670369297,
        ],
        num_partial_products: 9,
        num_lookup_polys: 0,
        num_lookup_selectors: 0,
        luts: vec![],
    }
}
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
    pub private_key: HashOutTarget,
    pub action_hash: HashOutTarget,
    // end circuit targets
    pub minifier_chain: OASProofMinifierChain<D, C::F, C>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub public_key: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for ZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new(self.public_key)
    }
}
impl<C: GenericConfig<D>, const D: usize> ZKSignatureCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
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
        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier_chain.prove(&inner_proof)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for ZKSignatureCircuit<C, D>
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
    let proof_inner = sig_circuit.prove_base(private_key, action_hash)?;
    let wrapper_circuit = ZKSignatureWrapperCircuit::<C, D>::new();
    let proof = wrapper_circuit.prove_base(&proof_inner, sig_circuit.get_verifier_config_ref())?;
    wrapper_circuit.circuit_data.verify(proof.clone())?;
    Ok(proof)
}
