use std::time::Duration;

use city_common::{cli::modes::QWorkerMode, logging::trace_timer::TraceTimer};
use city_rollup_circuit::worker::traits::{QWorkerGenericProverGroth16, QWorkerGenericProverMut};
use city_rollup_common::{
    actors::traits::WorkerEventReceiverSync,
    qworker::{
        job_id::{ProvingJobCircuitType, QJobTopic, QProvingJobDataID, QWorkerModeFilter},
        proof_store::QProofStore,
    },
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

pub struct SimpleActorWorker {}
impl SimpleActorWorker {
    pub fn run_worker<
        PS: QProofStore,
        ER: WorkerEventReceiverSync,
        G: QWorkerGenericProverMut<PS, C, D>
            + QWorkerGenericProverGroth16<PS, PoseidonGoldilocksConfig, 2>,
        C: GenericConfig<D>,
        const D: usize,
    >(
        store: &mut PS,
        event_receiver: &mut ER,
        prover: &mut G,
    ) -> anyhow::Result<()> {
        loop {
            Self::process_next_job(store, event_receiver, prover, QWorkerMode::All)?;
        }
    }
    pub fn process_next_job<
        PS: QProofStore,
        ER: WorkerEventReceiverSync,
        G: QWorkerGenericProverMut<PS, C, D>
            + QWorkerGenericProverGroth16<PS, PoseidonGoldilocksConfig, 2>,
        C: GenericConfig<D>,
        const D: usize,
    >(
        store: &mut PS,
        event_receiver: &mut ER,
        prover: &mut G,
        mode: QWorkerMode,
    ) -> anyhow::Result<()> {
        //let mut timer = TraceTimer::new("process_next_job");
        let job = event_receiver.wait_for_next_job()?;
        if mode.can_process_job(job) {
            tracing::info!("job: {:?}", job);
            Self::process_job(store, event_receiver, prover, job)?;
            //timer.lap("processed next job");
        } else {
            event_receiver.enqueue_jobs(&[job])?;
            std::thread::sleep(Duration::from_millis(750));
        }
        Ok(())
    }
    fn process_job<
        PS: QProofStore,
        ER: WorkerEventReceiverSync,
        G: QWorkerGenericProverMut<PS, C, D>
            + QWorkerGenericProverGroth16<PS, PoseidonGoldilocksConfig, 2>,
        C: GenericConfig<D>,
        const D: usize,
    >(
        store: &mut PS,
        event_receiver: &mut ER,
        prover: &mut G,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<()> {
        let mut timer = TraceTimer::new("process_job");
        if job_id.topic == QJobTopic::GenerateStandardProof {
            let start_time = std::time::Instant::now();
            let _ = match job_id.circuit_type {
                ProvingJobCircuitType::WrapFinalSigHashProofBLS12381 => {
                    // TODO: implement conversion from proof to bytes
                    let proof = G::worker_prove_groth16(prover, store, job_id)?;
                    let output_id = job_id.get_output_id();
                    store.set_bytes_by_id(output_id, &bincode::serialize(&proof)?)?;

                    output_id
                }
                _ => {
                    let proof = prover.worker_prove_mut(store, job_id)?;
                    let output_id = job_id.get_output_id();
                    store.set_proof_by_id(output_id, &proof)?;
                    output_id
                }
            };
            let duration = start_time.elapsed().as_millis() as u64;
            event_receiver.record_job_bench(job_id, duration)?;
        }
        if job_id.topic == QJobTopic::NotifyOrchestratorComplete {
            event_receiver.notify_core_goal_completed(job_id)?;
            return Ok(());
        }

        let goal_counter = store.get_goal_by_job_id(job_id)?;
        //tracing::info!("goal_counter: {}", goal_counter);
        if goal_counter != 0 {
            let result = store.inc_counter_by_id(job_id.get_sub_group_counter_id())?;
            if result == goal_counter {
                let jobs = store.get_next_jobs_by_job_id(job_id)?;
                //tracing::info!("[{:?}] enqueuing_jobs: {:?}", job_id, jobs);
                event_receiver.enqueue_jobs(&jobs)?;
            }
        }
        timer.event(format!(
            "processed job {} ({:?})",
            hex::encode(job_id.to_fixed_bytes()),
            job_id
        ));

        Ok(())
    }
}
