use async_trait::async_trait;

#[async_trait]
pub trait KeyValueStoreWithInc {
    async fn put(&mut self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn put_many(&mut self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()>;

    async fn get(&mut self, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn get_many(&mut self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<u8>>;

    async fn remove(&mut self, key: &[u8]) -> anyhow::Result<bool>;
    async fn remove_many(&mut self, keys: &[Vec<u8>]) -> anyhow::Result<usize>;

    async fn inc(&mut self, key: &[u8], value: u32) -> anyhow::Result<u32>;
}
#[async_trait]
pub trait ProvingDispatcher: KeyValueStoreWithInc {
    async fn dispatch(&mut self, topic: impl Into<u64> + Send + 'static, key: &[u8]) -> anyhow::Result<()>;
}

