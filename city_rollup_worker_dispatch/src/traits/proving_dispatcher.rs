use async_trait::async_trait;
use serde::Serialize;

#[async_trait]
pub trait ProvingDispatcher {
    async fn dispatch(
        &mut self,
        topic: &str,
        value: impl Serialize + Send + 'static,
    ) -> anyhow::Result<()>;
}
