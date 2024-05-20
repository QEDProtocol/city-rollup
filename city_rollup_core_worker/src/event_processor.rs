use std::time::Duration;

use city_rollup_common::{
    actors::traits::{WorkerEventReceiverSync, WorkerEventTransmitterSync},
    qworker::job_id::QProvingJobDataID,
};
use city_rollup_worker_dispatch::{
    implementations::redis::{QueueNotification, RedisQueue, Q_JOB, Q_NOTIFICATIONS},
    traits::{proving_dispatcher::ProvingDispatcher, proving_worker::ProvingWorkerListener},
};

#[derive(Clone)]
pub struct CityEventProcessor {
    pub job_queue: RedisQueue,
}
impl CityEventProcessor {
    pub fn new(dispatcher: RedisQueue) -> Self {
        Self {
            job_queue: dispatcher,
        }
    }
}
impl WorkerEventReceiverSync for CityEventProcessor {
    fn wait_for_next_job(&mut self) -> anyhow::Result<QProvingJobDataID> {
        if let Some(job) = self.job_queue.pop_one(Q_JOB)? {
            Ok(serde_json::from_slice(&job)?)
        } else {
            Err(anyhow::format_err!("No jobs in queue, note that CityEventProcessor::wait_for_next_job does not block the thread like other implementations of WorkerEventReceiverSync do."))
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
