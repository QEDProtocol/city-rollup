use city_crypto::hash::{merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut};
use plonky2::hash::hash_types::RichField;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CRWorkerToolboxCoreCircuitFingerprints<F: RichField> {
    pub network_magic: u64,

    pub zk_signature_wrapper: QHashOut<F>,
    pub l1_secp256k1_signature: QHashOut<F>,

    // state transition operations
    pub op_register_user: TPCircuitFingerprintConfig<F>,
    pub op_claim_l1_deposit: TPCircuitFingerprintConfig<F>,
    pub op_l2_transfer: TPCircuitFingerprintConfig<F>,
    pub op_add_l1_withdrawal: TPCircuitFingerprintConfig<F>,

    // state transition with events operations
    pub op_add_l1_deposit: TPCircuitFingerprintConfig<F>,
    pub op_process_l1_withdrawal: TPCircuitFingerprintConfig<F>,

    // operation aggregators
    pub agg_state_transition: QHashOut<F>,
    pub agg_state_transition_signed: QHashOut<F>,
    pub agg_state_transition_with_events: QHashOut<F>,
}
