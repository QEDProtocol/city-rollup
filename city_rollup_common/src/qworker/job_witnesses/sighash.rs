use city_crypto::hash::{merkle::core::MerkleProofCore, qhashout::QHashOut};
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::{
    introspection::rollup::{
        introspection::{BlockSpendIntrospectionHint, RefundSpendIntrospectionHint},
        introspection_result::BTCRollupIntrospectionFinalizedResult,
    },
    qworker::job_id::QProvingJobDataID,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRSigHashWrapperCircuitInput<F: RichField> {
    pub introspection_hint: BlockSpendIntrospectionHint,
    pub whitelist_inclusion_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRSigHashWrapperRefundCircuitInput<F: RichField> {
    pub introspection_hint: RefundSpendIntrospectionHint,
    pub whitelist_inclusion_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRSigHashFinalGLCircuitInput<F: RichField> {
    pub result: BTCRollupIntrospectionFinalizedResult<F>,
    pub state_transition_proof_id: QProvingJobDataID,
    pub sighash_introspection_proof_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRSigHashRootCircuitInput {
    pub sighash_final_gl_proof_id: QProvingJobDataID,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "")]
pub struct CRSigHashRefundFinalGLCircuitInput {
    pub sighash_introspection_proof_id: QProvingJobDataID,
}
