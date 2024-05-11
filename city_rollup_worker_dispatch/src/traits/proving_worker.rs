use async_trait::async_trait;

use crate::traits::proving_dispatcher::ProvingDispatcher;

#[async_trait]
pub trait ProvingWorkerListener: ProvingDispatcher {
    async fn subscribe<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<()>;

    async fn receive_one<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<Option<(String, Vec<u8>)>>;

    async fn receive_all<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
    ) -> anyhow::Result<Vec<(String, Vec<u8>)>>;

    async fn delete_message<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
        id: String,
    ) -> anyhow::Result<bool>;
}
