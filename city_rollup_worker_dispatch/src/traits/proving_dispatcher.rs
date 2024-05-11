use async_trait::async_trait;
use serde::Serialize;

#[async_trait]
pub trait ProvingDispatcher {
    async fn dispatch<const Q_KIND: u8>(
        &mut self,
        topic: impl Into<u64> + Send + 'static,
        key: impl Serialize + Send + 'static,
    ) -> anyhow::Result<()>;
}
