use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bb8_redis::bb8::PooledConnection;
use bb8_redis::bb8::{self};
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderAsync;
use city_rollup_common::qworker::proof_store::QProofStoreWriterAsync;
use plonky2::plonk::proof::ProofWithPublicInputs;
use redis::AsyncCommands;
use redis::RedisResult;
use redis::ToRedisArgs;
use rsmq_async::PooledRsmq;
use rsmq_async::RedisConnectionManager;
use rsmq_async::RsmqConnection;
use rsmq_async::RsmqMessage;

use crate::implementations::redis::rollup_key::PROOFS;
use crate::implementations::redis::rollup_key::PROOF_COUNTERS;
use crate::traits::proving_dispatcher::KeyValueStoreWithInc;
use crate::traits::proving_dispatcher::ProvingDispatcher;
use crate::traits::proving_worker::ProvingWorkerListener;

pub mod rollup_key;

#[derive(Clone)]
pub struct RedisStore {
    pool: bb8::Pool<RedisConnectionManager>,
    // we use queue here because pubsub is mpmc
    queue: PooledRsmq,
}

pub const Q_HIDDEN: Option<Duration> = Some(Duration::from_secs(600));
pub const Q_DELAY: Option<u32> = None;
pub const Q_CAP: Option<i32> = Some(-1);

pub const Q_TX: u8 = 0;
pub const Q_JOB: u8 = 1;
pub const Q_DEBUG: u8 = 2;

pub fn get_topic_from_qname(qname: &str) -> u32 {
    qname.split(":").next().unwrap_or("").parse().unwrap()
}

impl RedisStore {
    pub async fn new(uri: &str) -> Result<Self> {
        let client = redis::Client::open(uri)?;
        let manager = RedisConnectionManager::from_client(client)?;
        let pool = bb8::Pool::builder().build(manager).await?;
        let queue = PooledRsmq::new_with_pool(pool.clone(), false, None);
        Ok(Self { pool, queue })
    }

    pub async fn get_connection(&self) -> anyhow::Result<PooledConnection<RedisConnectionManager>> {
        Ok(self.pool.get().await?)
    }

    pub async fn hget<'a, K, F>(&'a mut self, key: K, field: F) -> Result<Vec<u8>>
    where
        K: ToRedisArgs + Send + Sync + 'a,
        F: ToRedisArgs + Send + Sync + 'a,
    {
        let result: RedisResult<Vec<u8>> = self.get_connection().await?.hget(key, field).await;
        result.map_err(|e| e.into())
    }
}

#[async_trait]
impl KeyValueStoreWithInc for RedisStore {
    async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut conn = self.pool.get().await?;
        conn.set(key, value).await?;
        Ok(())
    }

    async fn put_many(&mut self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> Result<()> {
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for (key, value) in keys.iter().zip(values.iter()) {
            pipeline.set(key, value);
        }
        pipeline
            .query_async(&mut *self.get_connection().await?)
            .await?;
        Ok(())
    }

    async fn get(&mut self, key: &[u8]) -> Result<Vec<u8>> {
        let result: RedisResult<Vec<u8>> = self.get_connection().await?.get(key).await;
        result.map_err(|e| e.into())
    }

    async fn get_many(&mut self, keys: &[Vec<u8>]) -> Result<Vec<u8>> {
        let result: RedisResult<Vec<Vec<u8>>> = self.get_connection().await?.get(keys).await;
        result
            .map(|values| values.into_iter().flatten().collect())
            .map_err(|e| e.into())
    }

    async fn remove(&mut self, key: &[u8]) -> Result<bool> {
        let result: RedisResult<bool> = self.get_connection().await?.del(key).await;
        result.map_err(|e| e.into())
    }

    async fn remove_many(&mut self, keys: &[Vec<u8>]) -> Result<usize> {
        let result: RedisResult<usize> = self.get_connection().await?.del(keys).await;
        result.map_err(|e| e.into())
    }

    async fn inc(&mut self, key: &[u8], value: u32) -> Result<u32> {
        let result: RedisResult<u32> = self.get_connection().await?.incr(key, value).await;
        result.map_err(|e| e.into())
    }
}

#[async_trait]
impl ProvingDispatcher for RedisStore {
    async fn dispatch<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
        value: &[u8],
    ) -> Result<()> {
        let qname = format!("{}:{}", Q_KIND, topic.into());
        if matches!(
            self.queue.get_queue_attributes(&qname).await,
            Err(rsmq_async::RsmqError::QueueNotFound)
        ) {
            // worker should be able to finish in 10 minutes, otherwise
            // other worker will pick up the task
            self.queue
                .create_queue(&qname, Q_HIDDEN, Q_HIDDEN, Q_CAP)
                .await?;
        }
        self.queue.send_message(&qname, value, None).await?;
        Ok(())
    }
}

#[async_trait]
impl ProvingWorkerListener for RedisStore {
    async fn subscribe<const Q_KIND: u8>(
        &mut self,
        _topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_next_message<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<Vec<u8>> {
        let qname = format!("{}:{}", Q_KIND, topic.into());
        match self
            .queue
            .receive_message::<Vec<u8>>(&qname, Q_HIDDEN)
            .await?
        {
            Some(RsmqMessage { message, .. }) => Ok(message),
            None => Err(anyhow::anyhow!("No message")),
        }
    }
}

#[async_trait]
impl QProofStoreReaderAsync for RedisStore {
    async fn get_proof_by_id<C: plonky2::plonk::config::GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut conn = self.get_connection().await?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec()).await?;
        Ok(bincode::deserialize(&data)?)
    }
}

#[async_trait]
impl QProofStoreWriterAsync for RedisStore {
    async fn set_proof_by_id<C: plonky2::plonk::config::GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        let mut conn = self.get_connection().await?;
        conn.hset_nx(
            PROOFS,
            <[u8; 24]>::from(&id).to_vec(),
            bincode::serialize(&proof)?,
        )
        .await?;
        Ok(())
    }

    async fn inc_counter_by_id<C: plonky2::plonk::config::GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32> {
        let mut conn = self.get_connection().await?;
        let value: u32 = conn
            .hincr(PROOF_COUNTERS, <[u8; 24]>::from(&id).to_vec(), 1)
            .await?;
        Ok(value)
    }
}
