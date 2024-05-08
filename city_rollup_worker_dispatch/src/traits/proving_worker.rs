use async_trait::async_trait;

use crate::traits::proving_dispatcher::ProvingDispatcher;

#[async_trait]
pub trait ProvingWorkerListener: ProvingDispatcher {
    async fn subscribe<const Q_KIND: u8>(&mut self, topic: impl Into<u64> + Send + 'static) -> anyhow::Result<()> ;
    async fn get_next_message<const Q_KIND: u8>(&mut self, topic: impl Into<u64> + Send + 'static) -> anyhow::Result<Vec<u8>>;
}
