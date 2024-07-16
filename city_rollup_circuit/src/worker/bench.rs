use std::{marker::PhantomData, time::Instant};

use city_crypto::hash::{merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut};
use city_rollup_common::{block_template::data::CityGroth16ProofData, qworker::{job_id::{ProvingJobCircuitType, QProvingJobDataID, QWorkerJobBenchmark}, proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper}};
use plonky2::plonk::{circuit_data::{CommonCircuitData, VerifierOnlyCircuitData}, config::GenericConfig, proof::ProofWithPublicInputs};

use super::traits::{QWorkerGenericProverGroth16, QWorkerGenericProverMut};

pub struct QWorkerGenericProverMutBench<P: QWorkerGenericProverMut<S, C, D>, S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize> {
  pub prover: P,
  pub benchmarks: Vec<QWorkerJobBenchmark>,
  _store: PhantomData<S>,
  _config: PhantomData<C>,
}

impl<P: QWorkerGenericProverMut<S, C, D>, S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize> QWorkerGenericProverMutBench<P, S, C, D> {
  pub fn new(prover: P) -> Self {
      Self {
          prover,
          benchmarks: Vec::new(),
          _store: PhantomData,
          _config: PhantomData,
      }
  }
  pub fn add_benchmark(&mut self, job_id: QProvingJobDataID, duration: u64) {
      self.benchmarks.push(QWorkerJobBenchmark {
          job_id: job_id.to_fixed_bytes(),
          duration,
      });
  }
  pub fn get_benchmarks(&self) -> &[QWorkerJobBenchmark] {
      &self.benchmarks
  }

}
impl <P: QWorkerGenericProverMut<S, C, D>, S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize> QWorkerVerifyHelper<C, D> for QWorkerGenericProverMutBench<P, S, C, D>  {
  fn get_tree_prover_fingerprint_config(
      &self,
      circuit_type: ProvingJobCircuitType,
  ) -> anyhow::Result<TPCircuitFingerprintConfig<C::F>> {
      self.prover.get_tree_prover_fingerprint_config(circuit_type)
  }

  fn get_verifier_triplet_for_circuit_type(
      &self,
      circuit_type: ProvingJobCircuitType,
  ) -> (
      &CommonCircuitData<C::F, D>,
      &VerifierOnlyCircuitData<C, D>,
      QHashOut<C::F>,
  ) {
      self.prover.get_verifier_triplet_for_circuit_type(circuit_type)
  }
}
impl<P: QWorkerGenericProverMut<S, C, D>, S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize> QWorkerGenericProverMut<S, C, D> for QWorkerGenericProverMutBench<P, S, C, D> {
  fn worker_prove_mut(
      &mut self,
      store: &S,
      job_id: QProvingJobDataID,
  ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
      let start_time = Instant::now();
      
      let result = self.prover.worker_prove_mut(store, job_id);
      if result.is_ok() {
          let duration = start_time.elapsed().as_millis() as u64;
          self.add_benchmark(job_id, duration);
      }
      result
  }
}
impl<P: QWorkerGenericProverMut<S, C, D> + QWorkerGenericProverGroth16<S, C, D>, S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize> QWorkerGenericProverGroth16<S, C, D> for QWorkerGenericProverMutBench<P, S, C, D> {
  fn worker_prove_groth16(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<CityGroth16ProofData> {
        self.prover.worker_prove_groth16(store, job_id)
    }
}