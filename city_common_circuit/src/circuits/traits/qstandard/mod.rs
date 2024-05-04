use async_trait::async_trait;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync};
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::GenericConfig,
    proof::ProofWithPublicInputs,
};
use serde::Serialize;

pub mod provable;
pub trait QStandardCircuit<C: GenericConfig<D>, const D: usize> {
    fn get_fingerprint(&self) -> QHashOut<C::F>;
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D>;
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D>;
    fn print_config(&self) {
        println!(
            "constants_sigmas_cap_height: {}",
            self.get_verifier_config_ref().constants_sigmas_cap.height()
        );
        println!("common_data: {:?}", self.get_common_circuit_data_ref());
    }
}

pub trait QStandardCircuitProvableWithProofStoreSync<
    S: QProofStoreReaderSync,
    I: Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &I,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
#[async_trait]
pub trait QStandardCircuitProvableWithProofStoreAsync<
    S: QProofStoreReaderAsync,
    I: Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        input: &I,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
