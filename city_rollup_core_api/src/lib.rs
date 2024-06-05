
use city_crypto::hash::base_types::hash160::Hash160;
use city_crypto::hash::base_types::hash256::Hash256;
use city_rollup_common::api::data::store::{
    CityL1Deposit, CityL1Withdrawal, CityL2BlockState, CityUserState,
};
use city_store::config::{CityHash, CityMerkleProof};
use city_store::store::city::base::CityStore;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::{ErrorCode, ErrorObject, ErrorObjectOwned};
use kvq_store_rocksdb::KVQRocksDBStore;

#[rpc(server, client, namespace = "cr")]
pub trait Rpc {
    #[method(name = "getUserTreeRoot")]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned>;

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
    ) -> Result<CityL1Deposit, ErrorObjectOwned>;

    #[method(name = "getDepositsById")]
    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> Result<Vec<CityL1Deposit>, ErrorObjectOwned>;

    #[method(name = "getDepositByTxid")]
    async fn get_deposit_by_txid(
        &self,
        transaction_id: Hash256,
    ) -> Result<CityL1Deposit, ErrorObjectOwned>;

    #[method(name = "getDepositsByTxid")]
    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> Result<Vec<CityL1Deposit>, ErrorObjectOwned>;

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
    db: KVQRocksDBStore,
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned> {
        Ok(CityStore::get_user_tree_root(&self.db, checkpoint_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> Result<CityUserState, ErrorObjectOwned> {
        Ok(CityStore::get_user_by_id(&self.db, checkpoint_id, user_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_user_merkle_proof_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(
            CityStore::get_user_merkle_proof_by_id(&self.db, checkpoint_id, user_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_user_tree_leaf(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(
            CityStore::get_user_tree_leaf(&self.db, checkpoint_id, leaf_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_user_tree_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(
            CityStore::get_user_tree_leaf_merkle_proof(&self.db, checkpoint_id, leaf_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_deposit_tree_root(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(CityStore::get_deposit_tree_root(&self.db, checkpoint_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_deposit_by_id(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityL1Deposit, ErrorObjectOwned> {
        Ok(
            CityStore::get_deposit_by_id(&self.db, checkpoint_id, deposit_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> Result<Vec<CityL1Deposit>, ErrorObjectOwned> {
        Ok(
            CityStore::get_deposits_by_id(&self.db, checkpoint_id, &deposit_ids)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_deposit_by_txid(
        &self,
        transaction_id: Hash256,
    ) -> Result<CityL1Deposit, ErrorObjectOwned> {
        Ok(CityStore::get_deposit_by_txid(&self.db, transaction_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> Result<Vec<CityL1Deposit>, ErrorObjectOwned> {
        Ok(CityStore::get_deposits_by_txid(&self.db, &transaction_ids)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_deposit_hash(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(
            CityStore::get_deposit_hash(&self.db, checkpoint_id, deposit_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_deposit_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(
            CityStore::get_deposit_leaf_merkle_proof(&self.db, checkpoint_id, deposit_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_block_state(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityL2BlockState, ErrorObjectOwned> {
        Ok(CityStore::get_block_state(&self.db, checkpoint_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_latest_block_state(&self) -> Result<CityL2BlockState, ErrorObjectOwned> {
        Ok(CityStore::get_latest_block_state(&self.db)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_city_root(&self, checkpoint_id: u64) -> Result<CityHash, ErrorObjectOwned> {
        Ok(CityStore::get_city_root(&self.db, checkpoint_id)
            .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?)
    }

    async fn get_city_block_script(&self, checkpoint_id: u64) -> Result<String, ErrorObjectOwned> {
        Ok(hex::encode(
            &CityStore::get_city_block_script(&self.db, checkpoint_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        ))
    }

    async fn get_city_block_deposit_address(
        &self,
        checkpoint_id: u64,
    ) -> Result<Hash160, ErrorObjectOwned> {
        Ok(
            CityStore::get_city_block_deposit_address(&self.db, checkpoint_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_city_block_deposit_address_string(
        &self,
        checkpoint_id: u64,
    ) -> Result<String, ErrorObjectOwned> {
        Ok(
            CityStore::get_city_block_deposit_address_string(&self.db, checkpoint_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_withdrawal_tree_root(
        &self,
        checkpoint_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(
            CityStore::get_withdrawal_tree_root(&self.db, checkpoint_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_withdrawal_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityL1Withdrawal, ErrorObjectOwned> {
        Ok(
            CityStore::get_withdrawal_by_id(&self.db, checkpoint_id, withdrawal_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_withdrawals_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> Result<Vec<CityL1Withdrawal>, ErrorObjectOwned> {
        Ok(
            CityStore::get_withdrawals_by_id(&self.db, checkpoint_id, &withdrawal_ids)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_withdrawal_hash(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityHash, ErrorObjectOwned> {
        Ok(
            CityStore::get_withdrawal_hash(&self.db, checkpoint_id, withdrawal_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }

    async fn get_withdrawal_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> Result<CityMerkleProof, ErrorObjectOwned> {
        Ok(
            CityStore::get_withdrawal_leaf_merkle_proof(&self.db, checkpoint_id, withdrawal_id)
                .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?,
        )
    }
}

pub async fn run_server(server_addr: String, db: KVQRocksDBStore) -> anyhow::Result<()> {
    let server = Server::builder().build(server_addr).await?;

    let rpc_server_impl = RpcServerImpl { db };
    let handle = server.start(rpc_server_impl.into_rpc());
    tokio::spawn(handle.stopped());
    Ok(futures::future::pending::<()>().await)
}
