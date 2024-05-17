use async_trait::async_trait;
use itertools::Itertools;
use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};

use super::job_id::QProvingJobDataID;

pub trait QProofStoreReaderSync {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>>;
}

pub trait QProofStoreWriterSync {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>;
    fn set_bytes_by_id(&mut self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()>;

    fn inc_counter_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32>;
    fn write_next_jobs(
        &mut self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let counter_id = jobs[0].get_sub_group_counter_id();
        let goal_id = counter_id.get_sub_group_counter_goal_id();
        let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
        self.set_bytes_by_id(counter_id, &u32::to_le_bytes(0))?;
        self.set_bytes_by_id(goal_id, &u32::to_le_bytes(jobs.len() as u32))?;
        self.set_bytes_by_id(next_jobs_id, &bincode::serialize(next_jobs)?)?;
        Ok(())
    }
}

pub trait QProofStore: QProofStoreReaderSync + QProofStoreWriterSync {}

impl <T: QProofStoreReaderSync + QProofStoreWriterSync> QProofStore for T {}

#[async_trait]
pub trait QProofStoreReaderAsync {
    async fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

#[async_trait]
pub trait QProofStoreWriterAsync {
    async fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<()>;

    async fn inc_counter_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32>;
}
