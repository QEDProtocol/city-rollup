use city_common::logging::trace_timer::TraceTimer;
use city_rollup_common::qworker::{
    job_id::{ProvingJobCircuitType, QProvingJobDataID},
    proof_store::QProofStore,
};
use plonky2::plonk::config::GenericConfig;

use crate::worker::traits::QWorkerCircuitCompressWithDataSync;

use super::traits::QWorkerGenericProver;

pub struct QWorkerStandardProver {
    pub timer: TraceTimer,
}

impl QWorkerStandardProver {
    pub fn new() -> Self {
        Self {
            timer: TraceTimer::new("worker"),
        }
    }
    pub fn prove<
        S: QProofStore,
        G: QWorkerGenericProver<S, C, D> + QWorkerCircuitCompressWithDataSync<S>,
        C: GenericConfig<D>,
        const D: usize,
    >(
        &mut self,
        store: &mut S,
        prover: &G,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<QProvingJobDataID> {
        let output_id = match job_id.circuit_type {
            ProvingJobCircuitType::GenerateFinalSigHashProofGroth16 => {
                let proof = <G as QWorkerCircuitCompressWithDataSync<S>>::prove_q_worker_compress(
                    prover, store, job_id,
                )?;
                let output_id = job_id.get_output_id();
                store.set_bytes_by_id(output_id, proof.as_bytes())?;
                output_id
            }
            _ => {
                let proof = prover.worker_prove(store, job_id)?;
                let output_id = job_id.get_output_id();
                store.set_proof_by_id(output_id, &proof)?;
                output_id
            }
        };

        Ok(output_id)
    }
}
