use std::sync::Arc;

use city_crypto::hash::base_types::hash160::Hash160;
use city_crypto::hash::base_types::hash256::Hash256;
use city_macros::define_table;
use city_rollup_common::api::data::store::{
    CityL1DepositJSON, CityL1Withdrawal, CityL2BlockState, CityUserState,
};
use city_store::config::{CityHash, CityMerkleProof};
use city_store::store::city::base::CityStore;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::{ErrorCode, ErrorObject, ErrorObjectOwned};
use kvq_store_redb::KVQReDBStore;
use redb::{Database, ReadOnlyTable, TableDefinition};

define_table! { KV, &[u8], &[u8] }

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
}

#[derive(Clone)]
pub struct RpcServerImpl {
    db: Arc<Database>,
}

impl RpcServerImpl {
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
impl RpcServer for RpcServerImpl {
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
            .into_iter().map(|x| x.to_json_variant()).collect::<Vec<_>>()
        )

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
}

pub async fn run_server(server_addr: String, db: Arc<Database>) -> anyhow::Result<()> {
    let server = Server::builder().build(server_addr).await?;

    let rpc_server_impl = RpcServerImpl { db };
    let handle = server.start(rpc_server_impl.into_rpc());
    tokio::spawn(handle.stopped());
    Ok(futures::future::pending::<()>().await)
}
