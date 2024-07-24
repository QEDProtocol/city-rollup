use city_rollup_common::{
    introspection::rollup::introspection::BlockSpendIntrospectionHint,
    qworker::{
        job_id::QProvingJobDataID,
        job_witnesses::sighash::{CRSigHashFinalGLCircuitInput, CRSigHashRootCircuitInput, CRSigHashWrapperCircuitInput},
        proof_store::QProofStore,
    },
};
use city_store::{config::F, store::sighash::SigHashMerkleTree};
use plonky2::hash::poseidon::PoseidonHash;

pub struct SigHashFinalizer {
    pub sighash_introspection_job_ids: Vec<QProvingJobDataID>,
    pub sighash_final_gl_job_ids: Vec<QProvingJobDataID>,
    pub sighash_root_job_ids: Vec<QProvingJobDataID>,
    pub wrap_sighash_final_bls12381_job_ids: Vec<QProvingJobDataID>,
}

impl SigHashFinalizer {
    pub fn finalize_sighashes<PS: QProofStore>(
        proof_store: &mut PS,
        sighash_whitelist_tree: &SigHashMerkleTree,
        checkpoint_id: u64,
        state_transition_root_job_id: QProvingJobDataID,
        hints: &[BlockSpendIntrospectionHint],
    ) -> anyhow::Result<Self> {
        let mut sighash_introspection_job_ids: Vec<QProvingJobDataID> = Vec::new();
        let mut sighash_final_gl_job_ids: Vec<QProvingJobDataID> = Vec::new();
        let mut sighash_root_job_ids: Vec<QProvingJobDataID> = Vec::new();
        let mut wrap_sighash_final_bls12381_job_ids: Vec<QProvingJobDataID> = Vec::new();
        for (i, hint) in hints.iter().enumerate() {
            let job_id = QProvingJobDataID::sighash_introspection_input_witness(checkpoint_id, i);
            let whitelist_inclusion_proof = sighash_whitelist_tree
                .get_proof_for_id(hint.get_config().get_gadget_config_id())?;
            let input = CRSigHashWrapperCircuitInput {
                introspection_hint: hint.clone(),
                whitelist_inclusion_proof,
            };
            let input_bytes = bincode::serialize(&input)?;
            proof_store.set_bytes_by_id(job_id, &input_bytes)?;
            sighash_introspection_job_ids.push(job_id);

            let final_job_id = QProvingJobDataID::sighash_final_input_witness(checkpoint_id, i);
            let input = CRSigHashFinalGLCircuitInput::<F> {
                result: hint
                    .get_introspection_result::<PoseidonHash, F>()
                    .get_finalized_result::<PoseidonHash>(),
                state_transition_proof_id: state_transition_root_job_id.get_output_id(),
                sighash_introspection_proof_id: job_id.get_output_id(),
            };
            proof_store.set_bytes_by_id(final_job_id, &bincode::serialize(&input)?)?;
            sighash_final_gl_job_ids.push(final_job_id);

            let root_job_id = QProvingJobDataID::sighash_root_input_witness(checkpoint_id, i);
            let input = CRSigHashRootCircuitInput {
                sighash_final_gl_proof_id: final_job_id.get_output_id()
            };
            proof_store.set_bytes_by_id(root_job_id, &bincode::serialize(&input)?)?;
            sighash_root_job_ids.push(root_job_id);

            let wrap_final_job_id =
                QProvingJobDataID::wrap_sighash_final_bls3812_input_witness(checkpoint_id, i);
            proof_store.set_bytes_by_id(
                wrap_final_job_id,
                &bincode::serialize(&root_job_id.get_output_id())?,
            )?;
            wrap_sighash_final_bls12381_job_ids.push(wrap_final_job_id);
        }

        Ok(Self {
            sighash_introspection_job_ids,
            sighash_final_gl_job_ids,
            sighash_root_job_ids,
            wrap_sighash_final_bls12381_job_ids,
        })
    }
}
