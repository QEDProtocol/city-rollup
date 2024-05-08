use async_trait::async_trait;

use crate::traits::proving_dispatcher::ProvingDispatcher;

#[async_trait]
pub trait ProvingWorkerListener: ProvingDispatcher {
    async fn subscribe(&mut self, topic: u32) -> anyhow::Result<()> ;
    async fn get_next_message(&mut self, topic: u32) -> anyhow::Result<Vec<u8>>;
}
