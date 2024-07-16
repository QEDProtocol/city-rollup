use std::time::Duration;

use city_rollup_common::{
    actors::traits::{WorkerEventReceiverSync, WorkerEventTransmitterSync},
    qworker::job_id::{QProvingJobDataID, QWorkerJobBenchmark},
};
use city_rollup_worker_dispatch::{
    implementations::redis::{QueueNotification, RedisQueue, Q_JOB, Q_NOTIFICATIONS},
    traits::{proving_dispatcher::ProvingDispatcher, proving_worker::ProvingWorkerListener},
};
#[derive(Clone)]
pub struct CityEventProcessor {
    pub job_queue: RedisQueue,
    pub benckmarks_enabled: bool,
    pub benchmarks: Vec<QWorkerJobBenchmark>,
}
impl CityEventProcessor {
    pub fn new(dispatcher: RedisQueue) -> Self {
        Self::new_with_config(dispatcher, false)
    }
    pub fn new_with_config(dispatcher: RedisQueue, benckmarks_enabled: bool) -> Self {
        Self {
            job_queue: dispatcher,
            benckmarks_enabled,
            benchmarks: Vec::new(),
        }
    }
}
impl WorkerEventReceiverSync for CityEventProcessor {
    fn wait_for_next_job(&mut self) -> anyhow::Result<QProvingJobDataID> {
        loop {
            let job = self.job_queue.pop_one(Q_JOB)?;
            if job.is_some() {
                return Ok(serde_json::from_slice(&job.unwrap())?)
            }else{
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        }
    }

    fn enqueue_jobs(&mut self, jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
        for job in jobs {
            self.job_queue.dispatch(Q_JOB, job.clone())?;
        }
        Ok(())
    }

    fn notify_core_goal_completed(&mut self, _job: QProvingJobDataID) -> anyhow::Result<()> {
        self.job_queue.dispatch(Q_NOTIFICATIONS, QueueNotification::CoreJobCompleted)?;
        Ok(())
    }
    
    fn record_job_bench(&mut self, job: QProvingJobDataID, duration: u64) -> anyhow::Result<()> {
        if self.benckmarks_enabled {
            self.benchmarks.push(QWorkerJobBenchmark {
                job_id: job.to_fixed_bytes(),
                duration,
            });
        }
        Ok(())
    }
}

impl WorkerEventTransmitterSync for CityEventProcessor {
    fn enqueue_jobs(&mut self, jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
        for job in jobs {
            self.job_queue.dispatch(Q_JOB, job.clone())?;
        }
        Ok(())
    }

    fn wait_for_block_proving_jobs(&mut self, _checkpoint_id: u64) -> anyhow::Result<bool> {
        loop {
            match self
                .job_queue
                .pop_one(Q_NOTIFICATIONS)?
                .map(|v| serde_json::from_slice::<QueueNotification>(&v))
            {
                Some(Ok(QueueNotification::CoreJobCompleted)) => return Ok::<_, anyhow::Error>(true),
                Some(Err(_)) | None => {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            }
        }
    }
}
