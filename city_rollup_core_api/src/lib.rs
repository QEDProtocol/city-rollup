use std::sync::Arc;

use city_common::data::kv::SimpleKVPair;
use city_common::data::u8bytes::U8Bytes;
use city_crypto::hash::base_types::hash160::Hash160;
use city_crypto::hash::base_types::hash256::Hash256;
use city_macros::define_table;
use city_rollup_common::api::data::store::{
    CityL1DepositJSON, CityL1Withdrawal, CityL2BlockState, CityUserState,
};
use city_rollup_common::qworker::job_id::{QProvingJobDataID, QProvingJobDataIDSerializedWrapped};
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use city_store::config::{CityHash, CityJobWitness, CityMerkleProof};
use city_store::store::city::base::CityStore;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::{ErrorCode, ErrorObject, ErrorObjectOwned};
use kvq_store_redb::KVQReDBStore;
use redb::{Database, ReadOnlyTable, TableDefinition};

define_table! { KV, &[u8], &[u8] }

use hyper::Method;
use tower_http::cors::{Any, CorsLayer};

#[rpc(server, client, namespace = "cr")]
pub trait Rpc {
    #[method(name = "getUserTreeRoot")]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getUserIdsForPublicKey")]
    async fn get_user_ids_for_public_key(
        &self,
        public_key: CityHash,
    ) -> Result<Vec<u64>, ErrorObjectOwned>;

    #[method(name = "getUserById")]
    async fn get_user_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> Result<CityUserState, ErrorObjectOwned>;

    #[method(name = "getUserMerkleProofById")]
    async fn get_user_merkle_proof_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned>;

    #[method(name = "getUserTreeLeaf")]
    async fn get_user_tree_leaf(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getUserTreeLeafMerkleProof")]
    async fn get_user_tree_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned>;

    #[method(name = "getDepositTreeRoot")]
    async fn get_deposit_tree_root(&self, checkpoint_id: u64)
        -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getDepositById")]
    async fn get_deposit_by_id(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityL1DepositJSON, ErrorObjectOwned>;

    #[method(name = "getDepositsById")]
    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> Result<Vec<CityL1DepositJSON>, ErrorObjectOwned>;

    #[method(name = "getDepositByTxid")]
    async fn get_deposit_by_txid(
        &self,
        transaction_id: Hash256,
    ) -> Result<CityL1DepositJSON, ErrorObjectOwned>;

    #[method(name = "getDepositsByTxid")]
    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> Result<Vec<CityL1DepositJSON>, ErrorObjectOwned>;

    #[method(name = "getDepositHash")]
    async fn get_deposit_hash(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getDepositLeafMerkleProof")]
    async fn get_deposit_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned>;

    #[method(name = "getBlockState")]
    async fn get_block_state(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityL2BlockState, ErrorObjectOwned>;

    #[method(name = "getLatestBlockState")]
    async fn get_latest_block_state(&self) -> Result<CityL2BlockState, ErrorObjectOwned>;

    #[method(name = "getCityRoot")]
    async fn get_city_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getCityBlockScript")]
    async fn get_city_block_script(&self, checkpoint_id: u64) -> Result<String, ErrorObjectOwned>;

    #[method(name = "getCityBlockDepositAddress")]
    async fn get_city_block_deposit_address(
        &self,
        checkpoint_id: u64,
    ) -> Result<Hash160, ErrorObjectOwned>;

    #[method(name = "getCityBlockDepositAddressString")]
    async fn get_city_block_deposit_address_string(
        &self,
        checkpoint_id: u64,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "getWithdrawalTreeRoot")]
    async fn get_withdrawal_tree_root(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getWithdrawalById")]
    async fn get_withdrawal_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityL1Withdrawal, ErrorObjectOwned>;

    #[method(name = "getWithdrawalsById")]
    async fn get_withdrawals_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> Result<Vec<CityL1Withdrawal>, ErrorObjectOwned>;

    #[method(name = "getWithdrawalHash")]
    async fn get_withdrawal_hash(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned>;

    #[method(name = "getWithdrawalLeafMerkleProof")]
    async fn get_withdrawal_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned>;

    #[method(name = "getProofStoreValue")]
    async fn get_proof_store_value(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> Result<U8Bytes, ErrorObjectOwned>;

    #[method(name = "getProofStoreValues")]
    async fn get_proof_store_values(
        &self,
        keys: Vec<QProvingJobDataIDSerializedWrapped>,
    ) -> Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>, ErrorObjectOwned>;

    #[method(name = "getProofStoreJobWitness")]
    async fn get_proof_store_job_witness(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> Result<CityJobWitness, ErrorObjectOwned>;

    #[method(name = "getProofStoreJobWitnesses")]
    async fn get_proof_store_job_witnesses(
        &self,
        keys: Vec<QProvingJobDataIDSerializedWrapped>,
    ) -> Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, CityJobWitness>>, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct RpcServerImpl<PS: QProofStoreReaderSync> {
    db: Arc<Database>,
    proof_store: PS,
}

impl<PS: QProofStoreReaderSync> RpcServerImpl<PS> {
    pub fn query_store<T>(
        &self,
        f: impl FnOnce(KVQReDBStore<ReadOnlyTable<&'static [u8], &'static [u8]>>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let rxn = self.db.begin_read()?;
        let table = rxn.open_table(KV)?;

        f(KVQReDBStore::new(table))
    }
}

#[async_trait]
impl<PS: QProofStoreReaderSync + Clone + Sync + Send + 'static> RpcServer for RpcServerImpl<PS> {
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_user_tree_root(&store, checkpoint_id)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> Result<CityUserState, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_user_by_id(&store, checkpoint_id, user_id)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_ids_for_public_key(
        &self,
        public_key: CityHash,
    ) -> Result<Vec<u64>, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_user_ids_for_public_key(&store, public_key)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_merkle_proof_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_user_merkle_proof_by_id(
                    &store,
                    checkpoint_id,
                    user_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_tree_leaf(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_user_tree_leaf(
                    &store,
                    checkpoint_id,
                    leaf_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_tree_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_user_tree_leaf_merkle_proof(
                    &store,
                    checkpoint_id,
                    leaf_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_deposit_tree_root(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_deposit_tree_root(&store, checkpoint_id)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_deposit_by_id(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityL1DepositJSON, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_deposit_by_id(
                    &store,
                    checkpoint_id,
                    deposit_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?
            .to_json_variant())
    }

    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> Result<Vec<CityL1DepositJSON>, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_deposits_by_id(
                    &store,
                    checkpoint_id,
                    &deposit_ids,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?
            .into_iter()
            .map(|x| x.to_json_variant())
            .collect::<Vec<_>>())
    }

    async fn get_deposit_by_txid(
        &self,
        transaction_id: Hash256,
    ) -> Result<CityL1DepositJSON, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_deposit_by_txid(
                    &store,
                    transaction_id.reversed(),
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?
            .to_json_variant())
    }

    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> Result<Vec<CityL1DepositJSON>, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_deposits_by_txid(
                    &store,
                    &transaction_ids
                        .into_iter()
                        .map(|x| x.reversed())
                        .collect::<Vec<_>>(),
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?
            .into_iter()
            .map(|x| x.to_json_variant())
            .collect::<Vec<_>>())
    }

    async fn get_deposit_hash(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_deposit_hash(
                    &store,
                    checkpoint_id,
                    deposit_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_deposit_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_deposit_leaf_merkle_proof(
                    &store,
                    checkpoint_id,
                    deposit_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_block_state(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityL2BlockState, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_block_state(&store, checkpoint_id)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_latest_block_state(&self) -> Result<CityL2BlockState, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_latest_block_state(&store)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_city_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_city_root(&store, checkpoint_id)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_city_block_script(&self, checkpoint_id: u64) -> Result<String, ErrorObjectOwned> {
        Ok(hex::encode(
            &self
                .query_store(|store| Ok(CityStore::get_city_block_script(&store, checkpoint_id)?))
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        ))
    }

    async fn get_city_block_deposit_address(
        &self,
        checkpoint_id: u64,
    ) -> Result<Hash160, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_city_block_deposit_address(
                    &store,
                    checkpoint_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_city_block_deposit_address_string(
        &self,
        checkpoint_id: u64,
    ) -> Result<String, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_city_block_deposit_address_string(
                    &store,
                    checkpoint_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_withdrawal_tree_root(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| Ok(CityStore::get_withdrawal_tree_root(&store, checkpoint_id)?))
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_withdrawal_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityL1Withdrawal, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_withdrawal_by_id(
                    &store,
                    checkpoint_id,
                    withdrawal_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_withdrawals_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> Result<Vec<CityL1Withdrawal>, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_withdrawals_by_id(
                    &store,
                    checkpoint_id,
                    &withdrawal_ids,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_withdrawal_hash(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_withdrawal_hash(
                    &store,
                    checkpoint_id,
                    withdrawal_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_withdrawal_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(self
            .query_store(|store| {
                Ok(CityStore::get_withdrawal_leaf_merkle_proof(
                    &store,
                    checkpoint_id,
                    withdrawal_id,
                )?)
            })
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_proof_store_value(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> Result<U8Bytes, ErrorObjectOwned> {
        let result = self
            .proof_store
            .get_bytes_by_id(
                QProvingJobDataID::try_from(key.0)
                    .map_err(|_| ErrorObject::from(ErrorCode::InvalidParams))?,
            )
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;

        Ok(U8Bytes(result))
    }
    async fn get_proof_store_values(
        &self,
        keys: Vec<QProvingJobDataIDSerializedWrapped>,
    ) -> Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>, ErrorObjectOwned>
    {
        let id_keys = keys
            .iter()
            .map(|x| {
                QProvingJobDataID::try_from(x.0)
                    .map_err(|_| ErrorObject::from(ErrorCode::InvalidParams))
            })
            .collect::<Result<Vec<QProvingJobDataID>, ErrorObjectOwned>>()?;

        id_keys.iter().map(|key|{
            let result = self.proof_store.get_bytes_by_id(*key).map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;
            Ok(SimpleKVPair{key: QProvingJobDataIDSerializedWrapped(key.to_fixed_bytes()), value: U8Bytes(result)})
        }).collect::<Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>, ErrorObjectOwned>>()
    }

    async fn get_proof_store_job_witness(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> Result<CityJobWitness, ErrorObjectOwned> {
        
        let job_id = QProvingJobDataID::try_from(key.0).map_err(|_| ErrorObject::from(ErrorCode::InvalidParams))?;

        let result = self.proof_store
            .get_bytes_by_id(job_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;
        let value = if result.len() == 0 {
            CityJobWitness::RawBytes(U8Bytes(vec![]))
        }else{
            CityJobWitness::try_deserialize_witness(job_id, &result).map_err(|_| ErrorObject::from(ErrorCode::InternalError))?
        };
        Ok(value)
    }

    async fn get_proof_store_job_witnesses(
        &self,
        keys: Vec<QProvingJobDataIDSerializedWrapped>,
    ) -> Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, CityJobWitness>>, ErrorObjectOwned> {
        let id_keys = keys.iter().map(|x| QProvingJobDataID::try_from(x.0).map_err(|_| ErrorObject::from(ErrorCode::InvalidParams))).collect::<Result<Vec<QProvingJobDataID>, ErrorObjectOwned>>()?;

        id_keys.iter().map(|key|{
            let result = self.proof_store.get_bytes_by_id(*key).map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;
            let value = if result.len() == 0 {
                CityJobWitness::RawBytes(U8Bytes(vec![]))
            }else{
                CityJobWitness::try_deserialize_witness(*key, &result).map_err(|_| ErrorObject::from(ErrorCode::InternalError))?
            };
            Ok(SimpleKVPair{key: QProvingJobDataIDSerializedWrapped(key.to_fixed_bytes()), value })
        }).collect::<Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, CityJobWitness>>, ErrorObjectOwned>>()

    }
}

pub async fn run_server<PS: QProofStoreReaderSync + Send + Sync + Clone + 'static>(
    server_addr: String,
    db: Arc<Database>,
    proof_store: PS,
) -> anyhow::Result<()> {

	let cors = CorsLayer::new()
        // Allow `POST` when accessing the resource
        .allow_methods([Method::POST])
        // Allow requests from any origin
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new().layer(cors);
    let server = Server::builder().set_http_middleware(middleware).build(server_addr).await?;


    let rpc_server_impl = RpcServerImpl { db, proof_store };
    let handle = server.start(rpc_server_impl.into_rpc());
    tokio::spawn(handle.stopped());
    Ok(futures::future::pending::<()>().await)
}
