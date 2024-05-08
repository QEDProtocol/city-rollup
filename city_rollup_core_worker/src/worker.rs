use std::time::Duration;

use city_common::cli::args::L2WorkerArgs;
use city_rollup_common::qworker::job_id::QJobTopic;
use city_rollup_worker_dispatch::{
    implementations::redis::RedisStore, traits::proving_worker::ProvingWorkerListener,
};

pub async fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    let mut redis_store = RedisStore::new(&args.redis_uri).await?;
    loop {
        if let Ok(message) = redis_store
            .get_next_message(QJobTopic::GenerateStandardProof as u32)
            .await
        {
            println!("Received message: {:?}", message);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
