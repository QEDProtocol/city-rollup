use anyhow::Result;
use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, AsyncCommands, RedisResult};

use crate::traits::proving_dispatcher::{KeyValueStoreWithInc, ProvingDispatcher};
#[derive(Clone)]
pub struct RedisStore {
    connection: MultiplexedConnection,
}

#[derive(Clone)]
pub struct RedisClient {
    pub client: redis::Client,
}
impl RedisClient {
    pub async fn get_store(&self) -> Result<RedisStore> {
        RedisStore::new(self).await
    }
}
impl RedisStore {
    pub async fn new(client: &RedisClient) -> Result<Self> {
        let connection = client.client.get_multiplexed_async_connection().await?;
        Ok(Self { connection })
    }
    pub fn new_client(uri: &str) -> Result<RedisClient> {
        Ok(RedisClient {
            client: redis::Client::open(uri)?,
        })
    }
}

#[async_trait]
impl KeyValueStoreWithInc for RedisStore {
    async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.connection.set(key, value).await?;
        Ok(())
    }

    async fn put_many(&mut self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> Result<()> {
        let mut pipeline = redis::pipe();
        for (key, value) in keys.iter().zip(values.iter()) {
            pipeline.set(key, value);
        }
        pipeline.query_async(&mut self.connection).await?;
        Ok(())
    }

    async fn get(&mut self, key: &[u8]) -> Result<Vec<u8>> {
        let result: RedisResult<Vec<u8>> = self.connection.get(key).await;
        result.map_err(|e| e.into())
    }

    async fn get_many(&mut self, keys: &[Vec<u8>]) -> Result<Vec<u8>> {
        let result: RedisResult<Vec<Vec<u8>>> = self.connection.get(keys).await;
        result
            .map(|values| values.into_iter().flatten().collect())
            .map_err(|e| e.into())
    }

    async fn remove(&mut self, key: &[u8]) -> Result<bool> {
        let result: RedisResult<bool> = self.connection.del(key).await;
        result.map_err(|e| e.into())
    }

    async fn remove_many(&mut self, keys: &[Vec<u8>]) -> Result<usize> {
        let result: RedisResult<usize> = self.connection.del(keys).await;
        result.map_err(|e| e.into())
    }

    async fn inc(&mut self, key: &[u8], value: u32) -> Result<u32> {
        let result: RedisResult<u32> = self.connection.incr(key, value).await;
        result.map_err(|e| e.into())
    }
}

#[async_trait]
impl ProvingDispatcher for RedisStore {
    async fn dispatch(&mut self, topic: u32, key: &[u8]) -> Result<()> {
        self.connection.publish(topic.to_string(), key).await?;
        Ok(())
    }
}
