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

pub const Q_TX: &'static str = "TX";
pub const Q_JOB: &'static str = "JOB";

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
    async fn dispatch(
        &mut self,
        topic: &str,
        value: impl Serialize + Send + 'static,
    ) -> Result<()> {
        if matches!(
            self.queue.get_queue_attributes(topic).await,
            Err(rsmq_async::RsmqError::QueueNotFound)
        ) {
            // worker should be able to finish in 10 minutes, otherwise
            // other worker will pick up the task
            self.queue
                .create_queue(topic, Q_HIDDEN, Q_DELAY, Q_CAP)
                .await?;
        }
        println!("dispatching message to queue: {}", topic);
        self.queue
            .send_message(topic, serde_json::to_vec(&value)?, None)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ProvingWorkerListener for RedisDispatcher {
    async fn subscribe(&mut self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn receive_one(&mut self, topic: &str) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        match self.queue.receive_message(topic, Q_HIDDEN).await? {
            Some(RsmqMessage { id, message, .. }) => Ok(Some((id, message))),
            None => Ok(None),
        }
    }

    async fn receive_all(&mut self, topic: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let mut result = Vec::new();
        while let Some(RsmqMessage { id, message, .. }) =
            self.queue.pop_message(topic).await?
        {
            result.push((id, message));
        }

        Ok(result)
    }

    async fn delete_message(&mut self, topic: &str, id: String) -> anyhow::Result<bool> {
        Ok(self.queue.delete_message(topic, &id).await?)
    }
}
