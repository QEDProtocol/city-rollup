use std::time::Duration;

use anyhow::Result;
use rsmq::PooledRsmq;
use rsmq::RedisConnectionManager;
use rsmq::RsmqConnection;
use rsmq::RsmqError;
use rsmq::RsmqMessage;
use serde::Serialize;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;

use crate::traits::proving_dispatcher::ProvingDispatcher;
use crate::traits::proving_worker::ProvingWorkerListener;

#[derive(Clone)]
pub struct RedisQueue {
    // we use queue here because pubsub is mpmc
    queue: PooledRsmq,
}

pub const Q_HIDDEN: Option<Duration> = Some(Duration::from_secs(600));
pub const Q_DELAY: Option<Duration> = None;
pub const Q_CAP: Option<i32> = Some(-1);

pub const Q_RPC_TOKEN_TRANSFER: &'static str = "RPC_TOKEN_TRANSFER";
pub const Q_RPC_CLAIM_DEPOSIT: &'static str = "RPC_CLAIM_DEPOSIT";
pub const Q_RPC_ADD_WITHDRAWAL: &'static str = "RPC_ADD_WITHDRAWAL";
pub const Q_RPC_REGISTER_USER: &'static str = "RPC_REGISTER_USER";

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

impl RedisQueue {
    pub fn new(uri: &str) -> Result<Self> {
        let client = redis::Client::open(uri)?;
        let manager = RedisConnectionManager::from_client(client)?;
        let queue = {
            let pool = r2d2::Pool::builder().build(manager)?;
            let mut queue = PooledRsmq::new_with_pool(pool, false, None);
            for q in &[
                Q_RPC_TOKEN_TRANSFER,
                Q_RPC_CLAIM_DEPOSIT,
                Q_RPC_ADD_WITHDRAWAL,
                Q_RPC_REGISTER_USER,
                Q_CMD,
                Q_JOB,
                Q_NOTIFICATIONS,
            ] {
                if matches!(
                    queue.get_queue_attributes(*q),
                    Err(RsmqError::QueueNotFound)
                ) {
                    let _ = queue.create_queue(*q, Q_HIDDEN, Q_DELAY, Q_CAP);
                }
            }
            Ok::<_, anyhow::Error>(queue)
        }?;
        Ok(Self { queue })
    }

    pub fn new_with_pool(pool: r2d2::Pool<RedisConnectionManager>) -> Result<Self> {
        let queue = PooledRsmq::new_with_pool(pool, false, None);
        Ok(Self { queue })
    }
}

impl ProvingDispatcher for RedisQueue {
    fn dispatch(
        self: &mut Self,
        topic: &'static str,
        value: impl Serialize + Send + 'static,
    ) -> Result<()> {
        println!("dispatching message to queue: {}", topic);
        self.queue
            .send_message(topic, serde_json::to_vec(&value)?, None)?;
        Ok(())
    }
}

impl ProvingWorkerListener for RedisQueue {
    fn subscribe(&mut self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn receive_one(
        &mut self,
        topic: &'static str,
        hidden: Option<Duration>,
    ) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        match self.queue.receive_message(topic, hidden)? {
            Some(RsmqMessage { id, message, .. }) => Ok(Some((id, message))),
            None => Ok(None),
        }
    }

    fn pop_one(&mut self, topic: &'static str) -> anyhow::Result<Option<Vec<u8>>> {
        match self.queue.pop_message(topic)? {
            Some(RsmqMessage { message, .. }) => Ok(Some(message)),
            None => Ok(None),
        }
    }

    fn receive_all(
        &mut self,
        topic: &'static str,
        hidden: Option<Duration>,
    ) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        let mut result = Vec::new();
        while let Some(RsmqMessage { id, message, .. }) =
            self.queue.receive_message(topic, hidden)?
        {
            result.push((id, message));
        }

        Ok(result)
    }

    fn pop_all(&mut self, topic: &'static str) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        while let Some(RsmqMessage { message, .. }) = self.queue.pop_message(topic)? {
            result.push(message);
        }

        Ok(result)
    }

    fn delete_message(&mut self, topic: &'static str, id: String) -> anyhow::Result<bool> {
        Ok(self.queue.delete_message(topic, &id)?)
    }

    fn is_empty(&mut self) -> bool {
        matches!(
            self.queue.get_queue_attributes(Q_JOB).map(|x|x.msgs == 0),
            Ok(true)
        )
    }
}
