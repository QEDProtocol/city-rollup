use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
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
    fn print_config_with_name(&self, name: &str) {
        /*let common_data_bytes = self
            .get_common_circuit_data_ref()
            .to_bytes(&gate_serializer)
            .unwrap();
        let common_data_hash = CoreSha256Hasher::hash_bytes(&common_data_bytes).to_hex_string();
        println!(
            "[{}] {{constants_sigmas_cap_height: {}, common_data_hash: {}}}",
            name,
            self.get_verifier_config_ref().constants_sigmas_cap.height(),
            common_data_hash,
        );
        */
        /*
        println!(
            "[{}] common_data: {:?}",
            name,
            self.get_common_circuit_data_ref()
        );
        */

        /*println!(
            "[{}] {{constants_sigmas_cap_height: {}}}",
            name,
            self.get_verifier_config_ref().constants_sigmas_cap.height(),
        );*/
        println!("{}: \"{:?}\",", name, self.get_common_circuit_data_ref());
    }
}

pub trait QStandardCircuitWithDefault {
    fn new_default(network_magic: u64) -> Self;
}
pub trait QStandardCircuitWithDefaultMinified {
    fn new_default_with_minifiers(network_magic: u64, n_minifiers: usize) -> Self;
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
