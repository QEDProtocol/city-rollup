use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bb8_redis::bb8::{self};
use rsmq_async::PooledRsmq;
use rsmq_async::RedisConnectionManager;
use rsmq_async::RsmqConnection;
use rsmq_async::RsmqMessage;
use serde::Serialize;

use crate::traits::proving_dispatcher::ProvingDispatcher;
use crate::traits::proving_worker::ProvingWorkerListener;

#[derive(Clone)]
pub struct RedisDispatcher {
    // we use queue here because pubsub is mpmc
    queue: PooledRsmq,
}

pub const Q_HIDDEN: Option<Duration> = Some(Duration::from_secs(600));
pub const Q_DELAY: Option<Duration> = None;
pub const Q_CAP: Option<i32> = Some(-1);

pub const Q_TX: u8 = 0;
pub const Q_JOB: u8 = 1;

impl RedisDispatcher {
    pub async fn new(uri: &str) -> Result<Self> {
        let client = redis::Client::open(uri)?;
        let manager = RedisConnectionManager::from_client(client)?;
        let pool = bb8::Pool::builder().build(manager).await?;
        let queue = PooledRsmq::new_with_pool(pool, false, None);
        Ok(Self { queue })
    }

    pub fn new_with_pool(pool: bb8::Pool<RedisConnectionManager>) -> Result<Self> {
        let queue = PooledRsmq::new_with_pool(pool, false, None);
        Ok(Self { queue })
    }
}

#[async_trait]
impl ProvingDispatcher for RedisDispatcher {
    async fn dispatch<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
        value: impl Serialize + Send + 'static,
    ) -> Result<()> {
        let qname = format!("{}_{}", Q_KIND, topic.into());
        if matches!(
            self.queue.get_queue_attributes(&qname).await,
            Err(rsmq_async::RsmqError::QueueNotFound)
        ) {
            // worker should be able to finish in 10 minutes, otherwise
            // other worker will pick up the task
            self.queue
                .create_queue(&qname, Q_HIDDEN, Q_DELAY, Q_CAP)
                .await?;
        }
        println!("dispatching message to queue: {}", qname);
        self.queue
            .send_message(&qname, serde_json::to_vec(&value)?, None)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ProvingWorkerListener for RedisDispatcher {
    async fn subscribe<const Q_KIND: u8>(
        &mut self,
        _topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn receive_one<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        let qname = format!("{}_{}", Q_KIND, topic.into());
        match self.queue.receive_message(&qname, Q_HIDDEN).await? {
            Some(RsmqMessage { id, message, .. }) => Ok(Some((id, message))),
            None => Ok(None),
        }
    }

    async fn receive_all<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let qname = format!("{}_{}", Q_KIND, topic.into());

        let mut result = Vec::new();
        while let Some(RsmqMessage { id, message, .. }) =
            self.queue.receive_message(&qname, Q_HIDDEN).await?
        {
            result.push((id, message));
        }

        Ok(result)
    }

    async fn delete_message<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
        id: String,
    ) -> anyhow::Result<bool> {
        let qname = format!("{}_{}", Q_KIND, topic.into());
        Ok(self.queue.delete_message(&qname, &id).await?)
    }
}
