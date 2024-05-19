use std::collections::VecDeque;

use crate::{actors::traits::WorkerEventReceiverSync, qworker::job_id::QProvingJobDataID};

pub struct CityEventProcessorMemory {
    pub job_queue: VecDeque<QProvingJobDataID>,
}
impl CityEventProcessorMemory {
    pub fn new() -> Self {
        Self {
            job_queue: VecDeque::new(),
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
        self.job_queue.extend(jobs.into_iter());
        Ok(())
    }

    fn notify_core_goal_completed(&mut self, _job: QProvingJobDataID) -> anyhow::Result<()> {
        //println!("CityEventProcessorMemory::notify_core_goal_completed is a no-op since its for local (sync) testing only.");
        Ok(())
    }
}
