use city_rollup_common::{
    introspection::{
        rollup::introspection::BlockSpendIntrospectionHint, transaction::BTCTransaction,
    },
    qworker::{
        job_id::QProvingJobDataID, job_witnesses::sighash::CRSigHashWrapperCircuitInput,
        proof_store::QProofStore,
    },
};
use city_store::store::sighash::SigHashMerkleTree;
use kvq::traits::KVQBinaryStore;

pub struct SigHashFinalizer {
    pub sighash_introspection_job_ids: Vec<QProvingJobDataID>,
}

impl SigHashFinalizer {
    pub fn finalize_sighashes<PS: QProofStore>(
        proof_store: &mut PS,
        sighash_whitelist_tree: SigHashMerkleTree,
        checkpoint_id: u64,
        state_transition_root_job_id: QProvingJobDataID,
        hints: &[BlockSpendIntrospectionHint],
    ) -> anyhow::Result<Self> {
        let mut sighash_introspection_job_ids: Vec<QProvingJobDataID> = Vec::new();
        for (i, hint) in hints.iter().enumerate() {
            let job_id = QProvingJobDataID::sighash_introspection_input_witness(checkpoint_id, i);
            let whitelist_inclusion_proof = sighash_whitelist_tree
                .get_proof_for_id(hint.get_config().get_gadget_config_id())?;
            let input = CRSigHashWrapperCircuitInput {
                introspection_hint: hint.clone(),
                whitelist_inclusion_proof,
            };
            let input_bytes = bincode::serialize(&input)?;
            proof_store.set_bytes_by_id(job_id, &input_bytes);
            sighash_introspection_job_ids.push(job_id);
        }

        Ok(Self {
            sighash_introspection_job_ids,
        })
    }
}
