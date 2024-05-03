use async_trait::async_trait;
use city_crypto::hash::base_types::hash256::Hash256;
use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};

use super::job_id::QProvingJobDataID;

pub trait QProofStoreReaderSync {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

pub trait QProofStoreWriterSync {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>;

    fn inc_counter_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32>;
}

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
