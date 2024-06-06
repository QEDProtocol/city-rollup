use city_common_circuit::{
    circuits::traits::qstandard::QStandardCircuit,
    hash::base_types::felthash248::CircuitBuilderFelt248Hash,
    proof_minifier::{
        pm_chain_dynamic::OASProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic,
    },
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID, job_witnesses::sighash::CRSigHashFinalGLCircuitInput,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    introspection::gadgets::rollup::introspection_result::BTCRollupIntrospectionFinalizedResultGadget,
    worker::traits::QWorkerCircuitCustomWithDataSync,
};
fn _reverse_endian_bits(bits: &[Target]) -> Vec<Target> {
    let mut byte_groups = bits.to_vec().chunks_exact(8).map(|chunk| {
        [
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]
    }).collect::<Vec<_>>();
    byte_groups.reverse();

    byte_groups.into_iter().flatten().collect::<Vec<_>>()
}
#[derive(Debug)]
pub struct CRSigHashFinalGLCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    // [START] circuit targets
    pub block_state_transition_proof_target: ProofWithPublicInputsTarget<D>,
    pub sighash_wrapper_proof_target: ProofWithPublicInputsTarget<D>,
    pub introspection_finalized_result_gadget: BTCRollupIntrospectionFinalizedResultGadget,
    // [END] circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub minifier: OASProofMinifierDynamicChain<D, C::F, C>,
    //pub tracer: DebugCircuitTracer,
}
impl<C: GenericConfig<D>, const D: usize> CRSigHashFinalGLCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        block_state_transition_verifier_data: &VerifierOnlyCircuitData<C, D>,
        block_state_transition_common_data: &CommonCircuitData<C::F, D>,
        sighash_wrapper_verifier_data: &VerifierOnlyCircuitData<C, D>,
        sighash_wrapper_common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let block_state_transition_proof_target =
            builder.add_virtual_proof_with_pis(block_state_transition_common_data);
        let block_state_transition_verifier_data_target =
            builder.constant_verifier_data(block_state_transition_verifier_data);

        let sighash_wrapper_proof_target =
            builder.add_virtual_proof_with_pis(sighash_wrapper_common_data);
        let sighash_wrapper_verifier_data_target =
            builder.constant_verifier_data(sighash_wrapper_verifier_data);

        builder.verify_proof::<C>(
            &block_state_transition_proof_target,
            &block_state_transition_verifier_data_target,
            block_state_transition_common_data,
        );
        builder.verify_proof::<C>(
            &sighash_wrapper_proof_target,
            &sighash_wrapper_verifier_data_target,
            sighash_wrapper_common_data,
        );
        let introspection_finalized_result_gadget =
            BTCRollupIntrospectionFinalizedResultGadget::add_virtual_to(&mut builder);

        let combined_hash = introspection_finalized_result_gadget
            .get_combined_hash::<C::Hasher, C::F, D>(&mut builder);
        let sighash_proof_combined_hash = HashOutTarget {
            elements: [
                sighash_wrapper_proof_target.public_inputs[0],
                sighash_wrapper_proof_target.public_inputs[1],
                sighash_wrapper_proof_target.public_inputs[2],
                sighash_wrapper_proof_target.public_inputs[3],
            ],
        };
        builder.connect_hashes(sighash_proof_combined_hash, combined_hash);

        let sighash_252 = HashOutTarget {
            elements: [
                sighash_wrapper_proof_target.public_inputs[4],
                sighash_wrapper_proof_target.public_inputs[5],
                sighash_wrapper_proof_target.public_inputs[6],
                sighash_wrapper_proof_target.public_inputs[7],
            ],
        };

        let expected_current_block_start_hash_248 =
            introspection_finalized_result_gadget.current_block_state_hash;
        let expected_current_block_end_hash_248 =
            introspection_finalized_result_gadget.next_block_state_hash;

        let actual_current_block_start_hash = HashOutTarget {
            elements: [
                block_state_transition_proof_target.public_inputs[0],
                block_state_transition_proof_target.public_inputs[1],
                block_state_transition_proof_target.public_inputs[2],
                block_state_transition_proof_target.public_inputs[3],
            ],
        };

        let actual_current_block_end_hash = HashOutTarget {
            elements: [
                block_state_transition_proof_target.public_inputs[4],
                block_state_transition_proof_target.public_inputs[5],
                block_state_transition_proof_target.public_inputs[6],
                block_state_transition_proof_target.public_inputs[7],
            ],
        };
        builder.connect_full_hashout_to_felt248_hashout(
            actual_current_block_start_hash,
            expected_current_block_start_hash_248,
        );
        builder.connect_full_hashout_to_felt248_hashout(
            actual_current_block_end_hash,
            expected_current_block_end_hash_248,
        );
        let expected_withdrawals_event_hash =
            introspection_finalized_result_gadget.withdrawals_hash;
        let expected_deposits_event_hash = introspection_finalized_result_gadget.deposits_hash;

        let actual_withdrawals_event_hash = HashOutTarget {
            elements: [
                block_state_transition_proof_target.public_inputs[8],
                block_state_transition_proof_target.public_inputs[9],
                block_state_transition_proof_target.public_inputs[10],
                block_state_transition_proof_target.public_inputs[11],
            ],
        };
        let actual_deposits_event_hash = HashOutTarget {
            elements: [
                block_state_transition_proof_target.public_inputs[12],
                block_state_transition_proof_target.public_inputs[13],
                block_state_transition_proof_target.public_inputs[14],
                block_state_transition_proof_target.public_inputs[15],
            ],
        };
        builder.connect_hashes(
            actual_withdrawals_event_hash,
            expected_withdrawals_event_hash,
        );
        builder.connect_hashes(actual_deposits_event_hash, expected_deposits_event_hash);
        let zero = builder.zero();
        let bits_block_start_hash = expected_current_block_start_hash_248
            .elements
            .iter()
            .map(|x| {
                builder
                    .split_le(*x, 64)
                    .iter()
                    .map(|b| b.target)
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>();
        let mut bits_sighash = sighash_252
            .elements
            .iter()
            .map(|x| {
                builder
                    .split_le(*x, 63)
                    .iter()
                    .map(|b| b.target)
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>()[0..248].to_vec();

        bits_sighash.append(&mut vec![zero, zero, zero, zero, zero, zero, zero, zero]);


        builder.register_public_inputs(&bits_block_start_hash);
        builder.register_public_inputs(&bits_sighash);
        let circuit_data = builder.build::<C>();

        let minifier = OASProofMinifierDynamicChain::new_with_dynamic_constant_verifier(
            &circuit_data.verifier_only,
            &circuit_data.common,
            &[false],
        );

        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, C::F, C>(
            &circuit_data.verifier_only,
        ));
        Self {
            block_state_transition_proof_target,
            sighash_wrapper_proof_target,
            introspection_finalized_result_gadget,
            circuit_data,
            fingerprint,
            minifier,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRSigHashFinalGLCircuitInput<C::F>,
        block_state_transition_proof: &ProofWithPublicInputs<C::F, C, D>,
        sighash_wrapper_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        println!("input: {:?}", input);
        println!(
            "block_state_transition_proof.public_inputs: {:?}",
            block_state_transition_proof.public_inputs
        );
        println!(
            "sighash_wrapper_proof.public_inputs: {:?}",
            sighash_wrapper_proof.public_inputs
        );
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(
            &self.block_state_transition_proof_target,
            block_state_transition_proof,
        );
        pw.set_proof_with_pis_target(&self.sighash_wrapper_proof_target, sighash_wrapper_proof);

        self.introspection_finalized_result_gadget
            .set_witness(&mut pw, &input.result);

        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRSigHashFinalGLCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier.get_common_data()
    }
}
impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitCustomWithDataSync<V, S, C, D> for CRSigHashFinalGLCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_q_worker_custom(
        &self,
        _verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_bytes = store.get_bytes_by_id(job_id)?;
        let input: CRSigHashFinalGLCircuitInput<C::F> = bincode::deserialize(&input_bytes)?;
        let block_state_transition_proof =
            store.get_proof_by_id(input.state_transition_proof_id)?;
        let sighash_wrapper_proof = store.get_proof_by_id(input.sighash_introspection_proof_id)?;
        self.prove_base(
            &input,
            &block_state_transition_proof,
            &sighash_wrapper_proof,
        )
    }
}
