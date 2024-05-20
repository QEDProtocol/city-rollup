use std::time::Duration;

use anyhow::Result;
use bb8_redis::bb8::{self};
use city_common::futures::block_on;
use city_macros::capture;
use rsmq_async::PooledRsmq;
use rsmq_async::RedisConnectionManager;
use rsmq_async::RsmqConnection;
use rsmq_async::RsmqMessage;
use serde::Serialize;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;

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
pub const Q_TOKEN_TRANSFER: &'static str = "TOKEN_TRANSFER";
pub const Q_CLAIM_DEPOSIT: &'static str = "CLAIM_DEPOSIT";
pub const Q_ADD_WITHDRAWAL: &'static str = "ADD_WITHDRAWAL";
pub const Q_REGISTER_USER: &'static str = "REGISTER_USER";
pub const Q_CMD: &'static str = "CMD";
pub const Q_JOB: &'static str = "JOB";
pub const Q_NOTIFICATIONS: &'static str = "NOTIFICATIONS";

#[derive(Clone, Copy, PartialEq, Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum QueueCmd {
    ProduceBlock = 0,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum QueueNotification {
    CoreJobCompleted = 0,
}

impl RedisDispatcher {
    pub fn new(uri: &str) -> Result<Self> {
        let client = redis::Client::open(uri)?;
        let manager = RedisConnectionManager::from_client(client)?;
        let pool = block_on(capture!(manager, async move {
            Ok::<_, anyhow::Error>(bb8::Pool::builder().build(manager).await?)
        }))?;
        let queue = PooledRsmq::new_with_pool(pool, false, None);
        Ok(Self { queue })
    }

    pub fn new_with_pool(pool: bb8::Pool<RedisConnectionManager>) -> Result<Self> {
        let queue = PooledRsmq::new_with_pool(pool, false, None);
        Ok(Self { queue })
    }
}

impl ProvingDispatcher for RedisDispatcher {
    fn dispatch(
        self: &mut Self,
        topic: &str,
        value: impl Serialize + Send + 'static,
    ) -> Result<()> {
        block_on(capture!(self => this, async move {
            if matches!(
                this.queue.get_queue_attributes(topic).await,
                Err(rsmq_async::RsmqError::QueueNotFound)
            ) {
                // worker should be able to finish in 10 minutes, otherwise
                // other worker will pick up the task
                this.queue
                    .create_queue(topic, Q_HIDDEN, Q_DELAY, Q_CAP)
                    .await?;
            }
            println!("dispatching message to queue: {}", topic);
            this.queue
                .send_message(topic, serde_json::to_vec(&value)?, None)
                .await?;
            Ok(())
        }))
    }
}

impl ProvingWorkerListener for RedisDispatcher {
    fn subscribe(&mut self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn receive_one(
        &mut self,
        topic: &str,
        hidden: Option<Duration>,
    ) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        block_on(capture!(self => this, async move {
            match this.queue.receive_message(topic, hidden).await? {
                Some(RsmqMessage { id, message, .. }) => Ok(Some((id, message))),
                None => Ok(None),
            }
        }))
    }

    fn pop_one(&mut self, topic: &str) -> anyhow::Result<Option<Vec<u8>>> {
        block_on(capture!(self => this, async move {
            match this.queue.pop_message(topic).await? {
                Some(RsmqMessage { message, .. }) => Ok(Some(message)),
                None => Ok(None),
            }
        }))
    }

    fn receive_all(
        &mut self,
        topic: &str,
        hidden: Option<Duration>,
    ) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        block_on(capture!(self => this, async move {
            let mut result = Vec::new();
            while let Some(RsmqMessage { id, message, .. }) =
                this.queue.receive_message(topic, hidden).await?
            {
                result.push((id, message));
            }

            Ok(result)
        }))
    }

    fn pop_all(&mut self, topic: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        block_on(capture!(self => this, async move {
            let mut result = Vec::new();
            while let Some(RsmqMessage { message, .. }) = this.queue.pop_message(topic).await? {
                result.push(message);
            }

            Ok(result)
        }))
    }

    fn delete_message(&mut self, topic: &str, id: String) -> anyhow::Result<bool> {
        block_on(capture!(self => this, async move {
            Ok(this.queue.delete_message(topic, &id).await?)
        }))
    }

    fn is_empty(&mut self, topic: &str) -> anyhow::Result<bool> {
        block_on(capture!(self => this, async move {
            Ok(this.queue.get_queue_attributes(topic).await?.msgs == 0)
        }))
    }
}
