use async_trait::async_trait;
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
}

pub trait QProofStore: QProofStoreReaderSync + QProofStoreWriterSync {}

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
