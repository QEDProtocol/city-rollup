use async_trait::async_trait;

use crate::traits::proving_dispatcher::ProvingDispatcher;

#[async_trait]
pub trait ProvingWorkerListener: ProvingDispatcher {
    async fn subscribe(&mut self, topic: &str) -> anyhow::Result<()>;
    async fn receive_one(&mut self, topic: &str) -> anyhow::Result<Option<(String, Vec<u8>)>>;
    async fn receive_all(&mut self, topic: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>>;
    async fn delete_message(&mut self, topic: &str, id: String) -> anyhow::Result<bool>;
}
