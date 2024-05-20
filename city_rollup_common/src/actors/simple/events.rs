use std::collections::VecDeque;

use crate::{
    actors::traits::{WorkerEventReceiverSync, WorkerEventTransmitterSync},
    qworker::job_id::QProvingJobDataID,
};

pub struct CityEventProcessorMemory {
    pub job_queue: VecDeque<QProvingJobDataID>,
    pub core_job_completed: bool,
}
impl CityEventProcessorMemory {
    pub fn new() -> Self {
        Self {
            job_queue: VecDeque::new(),
            core_job_completed: true,
        }
    }
}
impl WorkerEventReceiverSync for CityEventProcessorMemory {
    fn wait_for_next_job(&mut self) -> anyhow::Result<QProvingJobDataID> {
        if self.job_queue.is_empty() {
            Err(anyhow::format_err!("No jobs in queue, note that CityEventProcessorMemory::wait_for_next_job does not block the thread like other implementations of WorkerEventReceiverSync do."))
        } else {
            Ok(self.job_queue.pop_front().unwrap())
        }
    }

    fn enqueue_jobs(&mut self, jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
        self.core_job_completed = false;
        self.job_queue.extend(jobs.into_iter());
        Ok(())
    }

    fn notify_core_goal_completed(&mut self, _job: QProvingJobDataID) -> anyhow::Result<()> {
        self.core_job_completed = true;
        Ok(())
    }
}

impl WorkerEventTransmitterSync for CityEventProcessorMemory {
    fn enqueue_jobs(&mut self, jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
        self.job_queue.extend(jobs.into_iter());
        Ok(())
    }

    fn wait_for_block_proving_jobs(&mut self, _checkpoint_id: u64) -> anyhow::Result<bool> {
        if !self.core_job_completed {
            anyhow::bail!("core job not yet completed!");
        }
        //println!("CityEventProcessorMemory::wait_for_block_proving_jobs is a no-op since its for local (sync) testing only.");
        Ok(false)
    }
}
