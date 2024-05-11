use bb8_redis::bb8::PooledConnection;
use bb8_redis::bb8::{self};
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use redis::AsyncCommands;
use rsmq_async::RedisConnectionManager;
use serde::Deserialize;
use serde::Serialize;

// Table
pub const USER_REGISTRY: &'static str = "user_registry";
pub const BLOCK_STATE: &'static str = "block_state";

// Field
pub const USER_ID: &'static str = "user_id";
pub const USER_PUBKEY: &'static str = "user_pubkey";

pub const LAST_BLOCK_ID: &'static str = "last_block_id";
pub const LAST_ORCHESTOR_BLOCK_ID: &'static str = "last_orchestrator_block_id";
pub const LAST_BLOCK_TIMESTAMP: &'static str = "last_block_timestamp";
pub const TOKEN_TRANSFER_COUNTER: &'static str = "token_transfer_counter";
pub const USER_COUNTER: &'static str = "user_counter";
pub const CLAIM_L1_DEPOSIT_COUNTER: &'static str = "claim_l1_deposit_counter";
pub const DEPOSIT_COUNTER: &'static str = "deposit_counter";
pub const ADD_WITHDRWAL_COUNTER: &'static str = "add_withdrawal_counter";
pub const WITHDRWAL_COUNTER: &'static str = "withdrawal_counter";
pub const TASK_COUNTER: &'static str = "task_counter";

pub const NEXT_BLOCK_REDEEM_SCRIPT: &'static str = "next_block_redeem_script";

pub const PROOFS: &'static str = "proofs";
pub const PROOF_COUNTERS: &'static str = "proof_counters";

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;

#[derive(Clone)]
pub struct RedisStore {
    pool: bb8::Pool<RedisConnectionManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, Eq, PartialEq)]
pub struct ChainState {
    pub last_block_id: u64,
    pub last_orchestrator_block_id: u64,
    pub last_block_timestamp: u64,
    pub token_transfer_counter: u64,
    pub claim_l1_deposit_counter: u64,
    pub deposit_counter: u64,
    pub add_withdrawal_counter: u64,
    pub withdrawal_counter: u64,
    pub task_counter: u64,
    pub user_counter: u64,
}

impl RedisStore {
    pub async fn new(uri: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(uri)?;
        let manager = RedisConnectionManager::from_client(client)?;
        let pool = bb8::Pool::builder().build(manager).await?;
        Ok(Self { pool })
    }

    pub async fn get_connection(&self) -> anyhow::Result<PooledConnection<RedisConnectionManager>> {
        Ok(self.pool.get().await?)
    }

    pub fn get_pool(&self) -> bb8::Pool<RedisConnectionManager> {
        self.pool.clone()
    }

    pub async fn get_block_state_counter(&self, key: &str) -> anyhow::Result<u64> {
        let mut connection = self.get_connection().await?;
        let value: u64 = connection.hget(BLOCK_STATE, key).await?;
        Ok(value)
    }

    pub async fn get_block_state(&self) -> anyhow::Result<ChainState> {
        let mut connection = self.get_connection().await?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        let (
            last_block_id,
            last_orchestrator_block_id,
            last_block_timestamp,
            token_transfer_counter,
            claim_l1_deposit_counter,
            deposit_counter,
            add_withdrawal_counter,
            withdrawal_counter,
            user_counter,
            task_counter,
        ): (
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
            Option<u64>,
        ) = pipeline
            .hget(BLOCK_STATE, LAST_BLOCK_ID)
            .hget(BLOCK_STATE, LAST_ORCHESTOR_BLOCK_ID)
            .hget(BLOCK_STATE, LAST_BLOCK_TIMESTAMP)
            .hget(BLOCK_STATE, TOKEN_TRANSFER_COUNTER)
            .hget(BLOCK_STATE, CLAIM_L1_DEPOSIT_COUNTER)
            .hget(BLOCK_STATE, DEPOSIT_COUNTER)
            .hget(BLOCK_STATE, ADD_WITHDRWAL_COUNTER)
            .hget(BLOCK_STATE, WITHDRWAL_COUNTER)
            .hget(BLOCK_STATE, USER_COUNTER)
            .hget(BLOCK_STATE, TASK_COUNTER)
            .query_async(&mut *connection)
            .await?;

        Ok(ChainState {
            last_block_id: last_block_id.unwrap_or(0),
            last_orchestrator_block_id: last_orchestrator_block_id.unwrap_or(0),
            last_block_timestamp: last_block_timestamp.unwrap_or(0),
            token_transfer_counter: token_transfer_counter.unwrap_or(0),
            claim_l1_deposit_counter: claim_l1_deposit_counter.unwrap_or(0),
            deposit_counter: deposit_counter.unwrap_or(0),
            add_withdrawal_counter: add_withdrawal_counter.unwrap_or(0),
            withdrawal_counter: withdrawal_counter.unwrap_or(0),
            task_counter: task_counter.unwrap_or(0),
            user_counter: user_counter.unwrap_or(0),
        })
    }

    pub async fn incr_block_state_counter(&self, key: &str) -> anyhow::Result<(u64, u64)> {
        let mut connection = self.get_connection().await?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        let (next_counter, block_id): (u64, Option<u64>) = pipeline
            .hincr(BLOCK_STATE, key, 1)
            .hget(BLOCK_STATE, LAST_BLOCK_ID)
            .query_async(&mut *connection)
            .await?;

        Ok((next_counter - 1, block_id.unwrap_or(0)))
    }

    pub async fn get_user_public_key(&self, user_id: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let mut connection = self.get_connection().await?;
        let public_key: Option<Vec<u8>> = connection.hget(USER_REGISTRY, user_id).await?;
        Ok(public_key)
    }

    pub async fn get_user_id(&self, public_key: &[u8]) -> anyhow::Result<Option<u64>> {
        let mut connection = self.get_connection().await?;
        let user_id: Option<u64> = connection.hget(USER_REGISTRY, public_key).await?;
        Ok(user_id)
    }

    pub async fn get_next_block_redeem_script(&self) -> anyhow::Result<String> {
        let mut connection = self.get_connection().await?;
        Ok(connection.get(NEXT_BLOCK_REDEEM_SCRIPT).await?)
    }

    pub async fn register_user(&self, public_key: &[u8]) -> anyhow::Result<(u64, u64)> {
        let mut connection = self.get_connection().await?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        let user_id: Option<u64> = connection.hget(USER_REGISTRY, public_key).await?;
        if user_id.is_none() {
            let (user_counter, block_id): (u64, Option<u64>) = pipeline
                .hincr(BLOCK_STATE, USER_COUNTER, 1)
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query_async(&mut *connection)
                .await?;

            pipeline.clear();

            let user_id = user_counter - 1;
            pipeline
                .hset_nx(USER_REGISTRY, user_id, public_key)
                .ignore()
                .hset_nx(USER_REGISTRY, public_key, user_id)
                .ignore()
                .query_async(&mut *connection)
                .await?;

            Ok((user_id, block_id.unwrap_or(0)))
        } else {
            let (user_id, block_id): (u64, Option<u64>) = pipeline
                .hget(USER_REGISTRY, public_key)
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query_async(&mut *connection)
                .await?;

            Ok((user_id, block_id.unwrap_or(0)))
        }
    }

    pub async fn try_sequence_block(&self) -> anyhow::Result<u64> {
        let mut connection = self.get_connection().await?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        let (last_block_id, last_block_timestamp, (timestamp, _)): (
            Option<u64>,
            Option<u32>,
            (u32, u32),
        ) = pipeline
            .hget(BLOCK_STATE, LAST_BLOCK_ID)
            .hget(BLOCK_STATE, LAST_BLOCK_TIMESTAMP)
            .cmd("time")
            .query_async(&mut *connection)
            .await?;

        pipeline.clear();

        let block_id = if last_block_timestamp.is_none() {
            pipeline
                .hset(BLOCK_STATE, LAST_BLOCK_ID, 0)
                .ignore()
                .hset(BLOCK_STATE, LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query_async::<_, [u64; 1]>(&mut *connection)
                .await?[0]
        } else if timestamp - last_block_timestamp.unwrap() >= DEFAULT_BLOCK_TIME_IN_SECS {
            let nblocks =
                ((timestamp - last_block_timestamp.unwrap()) / DEFAULT_BLOCK_TIME_IN_SECS) as u64;
            let excess = (timestamp - last_block_timestamp.unwrap()) % DEFAULT_BLOCK_TIME_IN_SECS;
            let block_id: u64 = last_block_id.unwrap() + nblocks;
            pipeline
                .hset(BLOCK_STATE, LAST_BLOCK_ID, block_id)
                .ignore()
                .hset(BLOCK_STATE, LAST_BLOCK_TIMESTAMP, timestamp - excess)
                .ignore()
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query_async::<_, [u64; 1]>(&mut *connection)
                .await?[0]
        } else {
            pipeline
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query_async::<_, [u64; 1]>(&mut *connection)
                .await?[0]
        };

        Ok(block_id)
    }

    pub async fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut conn = self.get_connection().await?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec()).await?;
        Ok(bincode::deserialize(&data)?)
    }

    pub async fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>> {
        let mut conn = self.get_connection().await?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec()).await?;
        Ok(data)
    }

    pub async fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        let mut conn = self.get_connection().await?;
        conn.hset_nx(
            PROOFS,
            <[u8; 24]>::from(&id).to_vec(),
            bincode::serialize(&proof)?,
        )
        .await?;
        Ok(())
    }

    pub async fn inc_counter_by_id<C: plonky2::plonk::config::GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32> {
        let mut conn = self.get_connection().await?;
        let value: u32 = conn
            .hincr(PROOF_COUNTERS, <[u8; 24]>::from(&id).to_vec(), 1)
            .await?;
        Ok(value)
    }

    pub async fn set_bytes_by_id(
        &mut self,
        id: QProvingJobDataID,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let mut conn = self.get_connection().await?;
        conn.hset_nx(PROOFS, <[u8; 24]>::from(&id).to_vec(), data)
            .await?;
        Ok(())
    }
}
