use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use r2d2_redis::RedisConnectionManager;
use redis::Commands;

use crate::qworker::job_id::QProvingJobDataID;
use crate::qworker::proof_store::QProofStoreReaderSync;
use crate::qworker::proof_store::QProofStoreWriterSync;

pub const PROOFS: &'static str = "proofs";
pub const PROOF_COUNTERS: &'static str = "proof_counters";

#[derive(Clone)]
pub struct SyncRedisProofStore {
    pool: r2d2::Pool<RedisConnectionManager>,
}

impl SyncRedisProofStore {
    pub fn new(uri: &str) -> anyhow::Result<Self> {
        let manager = RedisConnectionManager::new(uri)?;
        let pool = r2d2::Pool::builder().build(manager)?;
        Ok(Self { pool })
    }

    pub fn get_connection(&self) -> anyhow::Result<r2d2::PooledConnection<RedisConnectionManager>> {
        Ok(self.pool.get()?)
    }
}

impl QProofStoreReaderSync for SyncRedisProofStore {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut conn = self.get_connection()?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec())?;
        Ok(bincode::deserialize(&data)?)
    }

    fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>> {
        let mut conn = self.get_connection()?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec())?;
        Ok(data)
    }
}

impl QProofStoreWriterSync for SyncRedisProofStore {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        let mut conn = self.get_connection()?;
        conn.hset_nx(
            PROOFS,
            <[u8; 24]>::from(&id).to_vec(),
            bincode::serialize(&proof)?,
        )?;
        Ok(())
    }

    fn inc_counter_by_id<C: plonky2::plonk::config::GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32> {
        let mut conn = self.get_connection()?;
        let value: u32 = conn.hincr(PROOF_COUNTERS, <[u8; 24]>::from(&id).to_vec(), 1)?;
        Ok(value)
    }

    fn set_bytes_by_id(&mut self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()> {
        let mut conn = self.get_connection()?;
        conn.hset_nx(PROOFS, <[u8; 24]>::from(&id).to_vec(), data)?;
        Ok(())
    }
}
