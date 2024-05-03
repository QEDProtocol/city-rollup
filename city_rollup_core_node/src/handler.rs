use std::sync::{Arc, Mutex};

use city_common::cli::args::RPCServerArgs;
use city_rollup_worker_dispatch::{
    implementations::redis::{RedisClient, RedisStore},
    traits::proving_dispatcher::KeyValueStoreWithInc,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RPCPutDataInputPayload {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub key: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RPCPutDataOutput {
    pub success: bool,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RPCGetDataInputPayload {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub key: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RPCGetDataOutput {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub key: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "cmd", content = "payload")]
pub enum RPCInputPayload {
    PutData(RPCPutDataInputPayload),
    GetData(RPCGetDataInputPayload),
}

#[derive(Clone)]
pub struct CityRollupRPCServerHandler {
    pub args: RPCServerArgs,
}
impl CityRollupRPCServerHandler {
    pub async fn new_handler(args: RPCServerArgs) -> anyhow::Result<Self> {
        //let dispatch = RedisStore::new(&client).await?;
        Ok(Self { args })
    }
    pub async fn rpc_put_data(
        &mut self,
        payload: RPCPutDataInputPayload,
    ) -> anyhow::Result<RPCPutDataOutput> {
        let client = RedisStore::new_client(&self.args.redis_uri)?;
        client
            .get_store()
            .await?
            .put(&payload.key, &payload.value)
            .await?;
        Ok(RPCPutDataOutput { success: true })
    }

    pub async fn rpc_get_data(
        &mut self,
        payload: RPCGetDataInputPayload,
    ) -> anyhow::Result<RPCGetDataOutput> {
        let client = RedisStore::new_client(&self.args.redis_uri)?;
        let value = client.get_store().await?.get(&payload.key).await?;
        Ok(RPCGetDataOutput {
            key: payload.key,
            value,
        })
    }

    pub async fn run_cmd(&mut self, cmd: RPCInputPayload) -> anyhow::Result<Vec<u8>> {
        match cmd {
            RPCInputPayload::PutData(payload) => {
                Ok(serde_json::to_vec(&self.rpc_put_data(payload).await?)?)
            }
            RPCInputPayload::GetData(payload) => {
                Ok(serde_json::to_vec(&self.rpc_get_data(payload).await?)?)
            }
        }
    }
}
