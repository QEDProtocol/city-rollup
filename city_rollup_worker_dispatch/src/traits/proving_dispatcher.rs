use serde::Serialize;

pub trait ProvingDispatcher {
    fn dispatch(
        &mut self,
        topic: &str,
        value: impl Serialize + Send + 'static,
    ) -> anyhow::Result<()>;
}
