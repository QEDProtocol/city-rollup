use city_crypto::hash::qhashout::QHashOut;
use plonky2::{hash::hash_types::RichField, plonk::config::AlgebraicHasher};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TPCircuitFingerprintConfig<F: RichField> {
    pub leaf_fingerprint: QHashOut<F>,
    pub aggregator_fingerprint: QHashOut<F>,
    pub allowed_circuit_hashes_root: QHashOut<F>,
}

impl<F: RichField> TPCircuitFingerprintConfig<F> {
    pub fn from_leaf_and_agg_fingerprints<H: AlgebraicHasher<F>>(
        leaf_fingerprint: QHashOut<F>,
        aggregator_fingerprint: QHashOut<F>,
    ) -> Self {
        let allowed_circuit_hashes_root =
            QHashOut(H::two_to_one(leaf_fingerprint.0, aggregator_fingerprint.0));
        Self {
            leaf_fingerprint,
            aggregator_fingerprint,
            allowed_circuit_hashes_root,
        }
    }
}
