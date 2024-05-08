use std::time::Duration;

use city_common::cli::args::OrchestratorArgs;
use city_macros::{async_infinite_loop, spawn_async_infinite_loop};
use city_rollup_common::qworker::job_id::QJobTopic;
use city_rollup_worker_dispatch::{
    implementations::redis::{
        rollup_key::{LAST_BLOCK_ID, LAST_BLOCK_TIMESTAMP},
        RedisStore,
    },
    traits::proving_worker::ProvingWorkerListener,
};
use redis::AsyncCommands;

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;

pub async fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    let redis_store = RedisStore::new(&args.redis_uri).await?;
    let redis_storec = redis_store.clone();

    spawn_async_infinite_loop! {
        let redis_storec = redis_storec.clone();
        let mut conn = redis_storec.get_connection().await?;

        let last_block_id: u64 = conn.get(LAST_BLOCK_ID).await.unwrap_or(0);
        let last_block_timestamp: u32 = conn.get(LAST_BLOCK_TIMESTAMP).await.unwrap_or(0);
        let (timestamp, _): (u32,u32) = redis::cmd("time").query_async(&mut *conn).await?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        if last_block_timestamp == 0 {
            pipeline
                .set(LAST_BLOCK_ID, 0)
                .ignore()
                .set(LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .query_async(&mut *conn)
                .await?;
        } else if timestamp - last_block_timestamp  >= DEFAULT_BLOCK_TIME_IN_SECS {
            let nblocks = ((timestamp - last_block_timestamp) / DEFAULT_BLOCK_TIME_IN_SECS) as u64;
            let block_id: u64 = last_block_id + nblocks;
            pipeline
                .set(LAST_BLOCK_ID, block_id)
                .ignore()
                .set(LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .query_async(&mut *conn)
                .await?;
        } else {
            // noop
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    async_infinite_loop! {
        if let Ok(message) = redis_store.clone().get_next_message(QJobTopic::BlockUserSignatureProof as u32).await {
            println!("Received message: {:?}", message);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
}
