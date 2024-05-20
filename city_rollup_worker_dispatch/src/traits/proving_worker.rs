use std::time::Duration;

use crate::traits::proving_dispatcher::ProvingDispatcher;

pub trait ProvingWorkerListener: ProvingDispatcher {
    fn subscribe(&mut self, topic: &str) -> anyhow::Result<()>;
    fn receive_one(&mut self, topic: &str, hidden: Option<Duration>) -> anyhow::Result<Option<(String, Vec<u8>)>>;
    fn pop_one(&mut self, topic: &str) -> anyhow::Result<Option<Vec<u8>>>;
    fn receive_all(&mut self, topic: &str, hidden: Option<Duration>) -> anyhow::Result<Vec<(String, Vec<u8>)>>;
    fn pop_all(&mut self, topic: &str) -> anyhow::Result<Vec<Vec<u8>>>;
    fn delete_message(&mut self, topic: &str, id: String) -> anyhow::Result<bool>;
    fn is_empty(&mut self, topic: &str) -> anyhow::Result<bool>;
}
