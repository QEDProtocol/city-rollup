use city_rollup_common::api::data::store::CityUserState;
use city_rollup_common::link::data::BTCOutpoint;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use city_rollup_common::qworker::proof_store::QProofStoreWriterSync;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use r2d2_redis::RedisConnectionManager;
use redis::Commands;

// Table
pub const USER_STATE: &'static str = "user_state";
pub const BLOCK_STATE: &'static str = "block_state";
pub const BLOCK_SPEND_INFO: &'static str = "block_spend_info";

// Field
pub const LAST_BLOCK_ID: &'static str = "last_block_id";
pub const LAST_BLOCK_TIMESTAMP: &'static str = "last_block_timestamp";

pub const CURRENT_BLOCK_REDEEM_SCRIPT: &'static str = "current_block_redeem_script";
pub const LAST_BLOCK_SPEND_OUTPUT: &'static str = "last_block_spend_output";

pub const PROOFS: &'static str = "proofs";
pub const PROOF_COUNTERS: &'static str = "proof_counters";

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;

#[derive(Clone)]
pub struct RedisStore {
    pool: r2d2::Pool<RedisConnectionManager>,
}

impl RedisStore {
    pub fn new(uri: &str) -> anyhow::Result<Self> {
        let manager = RedisConnectionManager::new(uri)?;
        let pool = r2d2::Pool::builder().build(manager)?;
        Ok(Self { pool })
    }

    pub fn get_connection(&self) -> anyhow::Result<r2d2::PooledConnection<RedisConnectionManager>> {
        Ok(self.pool.get()?)
    }

    pub fn get_pool(&self) -> r2d2::Pool<RedisConnectionManager> {
        self.pool.clone()
    }

    pub fn get_user_state(&self, user_id: u64) -> anyhow::Result<CityUserState> {
        let mut connection = self.get_connection()?;
        let data: Vec<u8> = connection.hget(USER_STATE, user_id)?;
        Ok(bincode::deserialize(&data)?)
    }

    pub fn get_block_state(&self) -> anyhow::Result<(u64, u64)> {
        let mut connection = self.get_connection()?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        let (last_block_id, last_block_timestamp): (Option<u64>, Option<u64>) = pipeline
            .hget(BLOCK_STATE, LAST_BLOCK_ID)
            .hget(BLOCK_STATE, LAST_BLOCK_TIMESTAMP)
            .query(&mut *connection)?;

        Ok((
            last_block_id.unwrap_or(0),
            last_block_timestamp.unwrap_or(0),
        ))
    }

    pub fn set_user_state(&self, user_state: &CityUserState) -> anyhow::Result<()> {
        let mut connection = self.get_connection()?;
        connection.hset(
            USER_STATE,
            user_state.user_id,
            bincode::serialize(user_state)?,
        )?;
        Ok(())
    }

    pub fn get_current_block_redeem_script(&self) -> anyhow::Result<Vec<u8>> {
        let mut connection = self.get_connection()?;
        let next_block_redeem_script: Vec<u8> =
            connection.hget(BLOCK_SPEND_INFO, CURRENT_BLOCK_REDEEM_SCRIPT)?;
        Ok(next_block_redeem_script)
    }

    pub fn set_current_block_redeem_script(
        &self,
        next_block_redeem_script: &Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut connection = self.get_connection()?;
        connection.hset(
            BLOCK_SPEND_INFO,
            CURRENT_BLOCK_REDEEM_SCRIPT,
            next_block_redeem_script,
        )?;
        Ok(())
    }

    pub fn get_last_block_spend_output(&self) -> anyhow::Result<Option<BTCOutpoint>> {
        let mut connection = self.get_connection()?;
        let last_block_spend_outpoint: Option<Vec<u8>> =
            connection.hget(BLOCK_SPEND_INFO, LAST_BLOCK_SPEND_OUTPUT)?;
        Ok(last_block_spend_outpoint.and_then(|x| bincode::deserialize(&x).ok()))
    }

    pub fn set_last_block_spend_output(&self, outpoint: BTCOutpoint) -> anyhow::Result<()> {
        let mut connection = self.get_connection()?;
        connection.hset(
            BLOCK_SPEND_INFO,
            LAST_BLOCK_SPEND_OUTPUT,
            &bincode::serialize(&outpoint)?,
        )?;
        Ok(())
    }

    pub fn sequence_block(&self) -> anyhow::Result<u64> {
        let mut connection = self.get_connection()?;
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
            .query(&mut *connection)?;

        pipeline.clear();

        let block_id = if last_block_timestamp.is_none() || last_block_id.is_none() {
            pipeline
                .hset(BLOCK_STATE, LAST_BLOCK_ID, 0)
                .ignore()
                .hset(BLOCK_STATE, LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query::<[u64; 1]>(&mut *connection)?[0]
        } else {
            pipeline
                .hset(BLOCK_STATE, LAST_BLOCK_ID, last_block_id.unwrap() + 1)
                .ignore()
                .hset(BLOCK_STATE, LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .hget(BLOCK_STATE, LAST_BLOCK_ID)
                .query::<[u64; 1]>(&mut *connection)?[0]
        };

        Ok(block_id)
    }
}

impl QProofStoreReaderSync for RedisStore {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut conn = self.get_connection()?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec())?;
        Ok(bincode::deserialize(&data)?)
    }

    fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>> {
        let mut conn = self.get_connection()?;
        let data: Vec<u8> = conn.hget(PROOFS, <[u8; 24]>::from(&id).to_vec())?;
        Ok(data)
    }
}

impl QProofStoreWriterSync for RedisStore {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        let mut conn = self.get_connection()?;
        conn.hset_nx(
            PROOFS,
            <[u8; 24]>::from(&id).to_vec(),
            bincode::serialize(&proof)?,
        )?;
        Ok(())
    }

    fn inc_counter_by_id<C: plonky2::plonk::config::GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<u32> {
        let mut conn = self.get_connection()?;
        let value: u32 = conn.hincr(PROOF_COUNTERS, <[u8; 24]>::from(&id).to_vec(), 1)?;
        Ok(value)
    }

    fn set_bytes_by_id(&mut self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()> {
        let mut conn = self.get_connection()?;
        conn.hset_nx(PROOFS, <[u8; 24]>::from(&id).to_vec(), data)?;
        Ok(())
    }
}
