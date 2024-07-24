use crate::worker::traits::QWorkerCircuitCustomWithDataSync;
use city_common_circuit::{
    builder::{
        connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
        verify::CircuitBuilderVerifyProofHelpers,
    },
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::{
        pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic,
    },
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::{
    job_id::{ProvingJobCircuitType, QProvingJobDataID}, job_witnesses::sighash::CRSigHashRootCircuitInput, proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper
};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

#[derive(Debug)]
pub struct CRSigHashRootCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    // [START] circuit targets
    pub sighash_final_gl_proof_target: ProofWithPublicInputsTarget<D>,
    pub sighash_final_gl_verifier_data_target: VerifierCircuitTarget,
    // [END] circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub minifier: QEDProofMinifierDynamicChain<D, C::F, C>,
    //pub tracer: DebugCircuitTracer,
}
impl<C: GenericConfig<D>, const D: usize> CRSigHashRootCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        cap_height: usize,
        block_state_transition_fingerprint: QHashOut<C::F>,
        dummy_block_state_transition_fingerprint: QHashOut<C::F>,
        common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let sighash_final_gl_proof_target = builder.add_virtual_proof_with_pis(common_data);
        let sighash_final_gl_verifier_data_target = builder.add_virtual_verifier_data(cap_height);

        builder.verify_proof::<C>(
            &sighash_final_gl_proof_target,
            &sighash_final_gl_verifier_data_target,
            common_data,
        );

        builder.register_public_inputs(&sighash_final_gl_proof_target.public_inputs);

        let allowed_fingerprints = [
            builder.constant_whash(block_state_transition_fingerprint),
            builder.constant_whash(dummy_block_state_transition_fingerprint),
        ];
        let actual_fingerprint =
            builder.get_circuit_fingerprint::<C::Hasher>(&sighash_final_gl_verifier_data_target);
        builder.connect_hashes_enum(actual_fingerprint, &allowed_fingerprints);

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
            sighash_final_gl_proof_target,
            sighash_final_gl_verifier_data_target,
            circuit_data,
            fingerprint,
            minifier,
        }
    }
    pub fn prove_base(
        &self,
        sighash_final_gl_proof: &ProofWithPublicInputs<C::F, C, D>,
        sighash_final_gl_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.sighash_final_gl_proof_target, sighash_final_gl_proof);
        pw.set_verifier_data_target(
            &self.sighash_final_gl_verifier_data_target,
            sighash_final_gl_verifier_data,
        );

        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRSigHashRootCircuit<C, D>
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
    > QWorkerCircuitCustomWithDataSync<V, S, C, D> for CRSigHashRootCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_q_worker_custom(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_bytes = store.get_bytes_by_id(job_id)?;
        let input: CRSigHashRootCircuitInput = bincode::deserialize(&input_bytes)?;
        let sighash_final_gl_proof = store.get_proof_by_id(input.sighash_final_gl_proof_id)?;
        self.prove_base(
            &sighash_final_gl_proof,
            &verify_helper.get_verifier_triplet_for_circuit_type(
                ProvingJobCircuitType::GenerateFinalSigHashProof,
            ).1
        )
    }
}
