use city_common_circuit::{
    circuits::traits::qstandard::QStandardCircuit, hash::base_types::felthash248::CircuitBuilderFelt248Hash, proof_minifier::{
        pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic,
    }
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::{introspection::rollup::introspection_result::BTCRollupRefundIntrospectionFinalizedResult, qworker::{
    job_id::QProvingJobDataID, job_witnesses::sighash::CRSigHashRefundFinalGLCircuitInput,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
}};
use plonky2::{
    gates::noop::NoopGate, hash::hash_types::HashOutTarget, iop::witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    }
};
use crate::{introspection::gadgets::rollup::refund_result::BTCRollupRefundIntrospectionFinalizedResultGadget, worker::traits::QWorkerCircuitCustomWithDataSync};

#[derive(Debug)]
pub struct CRSigHashRefundFinalGLCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    // [START] circuit targets
    pub sighash_refund_proof_target: ProofWithPublicInputsTarget<D>,
    pub introspection_finalized_result_gadget: BTCRollupRefundIntrospectionFinalizedResultGadget,
    // [END] circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub minifier: QEDProofMinifierDynamicChain<D, C::F, C>,
    //pub tracer: DebugCircuitTracer,
}
impl<C: GenericConfig<D>, const D: usize> CRSigHashRefundFinalGLCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        sighash_refund_verifier_data: &VerifierOnlyCircuitData<C, D>,
        sighash_refund_common_data: &CommonCircuitData<C::F, D>,
        expected_degree: usize
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let sighash_refund_proof_target =
            builder.add_virtual_proof_with_pis(sighash_refund_common_data);
        let sighash_refund_verifier_data_target =
            builder.constant_verifier_data(sighash_refund_verifier_data);

        let introspection_finalized_result_gadget =
            BTCRollupRefundIntrospectionFinalizedResultGadget::add_virtual_to(&mut builder);
        let expected_start_hash = introspection_finalized_result_gadget.current_block_state_hash;

        builder.verify_proof::<C>(
            &sighash_refund_proof_target,
            &sighash_refund_verifier_data_target,
            sighash_refund_common_data,
        );

        let actual_start_hash = HashOutTarget {
            elements: [
                sighash_refund_proof_target.public_inputs[0],
                sighash_refund_proof_target.public_inputs[1],
                sighash_refund_proof_target.public_inputs[2],
                sighash_refund_proof_target.public_inputs[3],
            ],
        };

        builder.connect_full_hashout_to_felt248_hashout(
            actual_start_hash,
            expected_start_hash
        );

        let sighash_252 = HashOutTarget {
            elements: [
                sighash_refund_proof_target.public_inputs[4],
                sighash_refund_proof_target.public_inputs[5],
                sighash_refund_proof_target.public_inputs[6],
                sighash_refund_proof_target.public_inputs[7],
            ],
        };

        let zero = builder.zero();
        let bits_block_start_hash = expected_start_hash
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

        if builder.num_gates() < expected_degree {
            for _ in 0..expected_degree - builder.num_gates() {
                builder.add_gate(NoopGate, vec![]);
            }
        }
        let circuit_data = builder.build::<C>();

        let minifier = QEDProofMinifierDynamicChain::new_with_dynamic_constant_verifier(
            &circuit_data.verifier_only,
            &circuit_data.common,
            &[false],
        );

        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, C::F, C>(
            &circuit_data.verifier_only,
        ));
        Self {
            sighash_refund_proof_target,
            introspection_finalized_result_gadget,
            circuit_data,
            fingerprint,
            minifier,
        }
    }
    pub fn prove_base(
        &self,
        sighash_refund_proof: &ProofWithPublicInputs<C::F, C, D>,
        result: &BTCRollupRefundIntrospectionFinalizedResult<C::F>
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.sighash_refund_proof_target, sighash_refund_proof);

        self.introspection_finalized_result_gadget
            .set_witness(&mut pw, &result);

        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRSigHashRefundFinalGLCircuit<C, D>
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
    > QWorkerCircuitCustomWithDataSync<V, S, C, D> for CRSigHashRefundFinalGLCircuit<C, D>
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
        let input: CRSigHashRefundFinalGLCircuitInput<C::F> = bincode::deserialize(&input_bytes)?;
        let sighash_refund_proof = store.get_proof_by_id(input.sighash_refund_proof_id)?;
        self.prove_base(
            &sighash_refund_proof,
            &input.result
        )
    }
}
