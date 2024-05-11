use city_crypto::hash::{merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::GenericConfig,
};

use super::job_id::ProvingJobCircuitType;

pub trait QWorkerVerifyHelper<C: GenericConfig<D>, const D: usize> {
    fn get_tree_prover_fingerprint_config(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<TPCircuitFingerprintConfig<C::F>>;

    fn get_verifier_triplet_for_circuit_type(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> (
        &CommonCircuitData<C::F, D>,
        &VerifierOnlyCircuitData<C, D>,
        QHashOut<C::F>,
    );
}
