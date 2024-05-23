use std::sync::Arc;

use city_crypto::hash::base_types::hash160::Hash160;
use city_crypto::hash::base_types::hash256::Hash256;
use city_macros::{city_external_rpc_call, city_rpc_call};
use city_rollup_common::api::data::{
    block::rpc_request::*,
    store::{CityL1Deposit, CityL1Withdrawal, CityL2BlockState, CityUserState},
};
use city_rollup_core_node::rpc::{
    ExternalRequestParams, Id, RequestParams, ResponseResult, RpcParams, RpcRequest, RpcResponse,
    Version,
};
use city_store::config::{CityHash, CityMerkleProof};
use plonky2::hash::hash_types::RichField;
use reqwest::Client;
use serde_json::json;

#[derive(Clone, Debug)]
pub struct RpcProvider {
    client: Arc<Client>,
    url: &'static str,
}

impl RpcProvider {
    pub fn new(url: &str) -> Self {
        Self {
            client: Arc::new(Client::new()),
            url: Box::leak(url.to_string().into_boxed_str()),
        }
    }
}

#[async_trait::async_trait]
pub trait CityRpcProvider {
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    async fn get_user_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityUserState>;

    async fn get_user_merkle_proof_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    async fn get_user_tree_leaf(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityHash>;

    async fn get_user_tree_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    async fn get_deposit_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    async fn get_deposit_by_id(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1Deposit>;

    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1Deposit>>;

    async fn get_deposit_by_txid(&self, transaction_id: Hash256) -> anyhow::Result<CityL1Deposit>;

    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> anyhow::Result<Vec<CityL1Deposit>>;

    async fn get_deposit_hash(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityHash>;

    async fn get_deposit_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    async fn get_block_state(&self, checkpoint_id: u64) -> anyhow::Result<CityL2BlockState>;

    async fn get_latest_block_state(&self) -> anyhow::Result<CityL2BlockState>;

    async fn get_city_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    async fn get_city_block_script(&self, checkpoint_id: u64) -> anyhow::Result<String>;

    async fn get_city_block_deposit_address(&self, checkpoint_id: u64) -> anyhow::Result<Hash160>;

    async fn get_city_block_deposit_address_string(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<String>;

    async fn get_withdrawal_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    async fn get_withdrawal_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal>;

    async fn get_withdrawals_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1Withdrawal>>;

    async fn get_withdrawal_hash(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityHash>;

    async fn get_withdrawal_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    async fn register_user<F: RichField>(
        &self,
        req: CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()>;

    async fn add_withdrawal<F: RichField>(
        &self,
        req: CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()>;

    async fn claim_deposit<F: RichField>(
        &self,
        req: CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()>;

    async fn token_transfer<F: RichField>(
        &self,
        req: CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl CityRpcProvider for RpcProvider {
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(self, "cr_getUserTreeRoot", json!([checkpoint_id]), CityHash)
    }

    async fn get_user_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityUserState> {
        city_external_rpc_call!(
            self,
            "cr_getUserById",
            json!([checkpoint_id, user_id]),
            CityUserState
        )
    }

    async fn get_user_merkle_proof_by_id(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call!(
            self,
            "cr_getUserMerkleProofById",
            json!([checkpoint_id, user_id]),
            CityMerkleProof
        )
    }

    async fn get_user_tree_leaf(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(
            self,
            "cr_getUserTreeLeaf",
            json!([checkpoint_id, leaf_id]),
            CityHash
        )
    }

    async fn get_user_tree_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call!(
            self,
            "cr_getUserTreeLeafMeckleProof",
            json!([checkpoint_id, leaf_id]),
            CityMerkleProof
        )
    }

    async fn get_deposit_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(
            self,
            "cr_getDepositTreeRoot",
            json!([checkpoint_id]),
            CityHash
        )
    }

    async fn get_deposit_by_id(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1Deposit> {
        city_external_rpc_call!(
            self,
            "cr_getDepositById",
            json!([checkpoint_id, deposit_id]),
            CityL1Deposit
        )
    }

    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1Deposit>> {
        city_external_rpc_call!(
            self,
            "cr_getDepositsById",
            json!([checkpoint_id, deposit_ids]),
            Vec<CityL1Deposit>
        )
    }

    async fn get_deposit_by_txid(&self, transaction_id: Hash256) -> anyhow::Result<CityL1Deposit> {
        city_external_rpc_call!(
            self,
            "cr_getDepositByTxid",
            json!([transaction_id]),
            CityL1Deposit
        )
    }

    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> anyhow::Result<Vec<CityL1Deposit>> {
        city_external_rpc_call!(
            self,
            "cr_getDepositsByTxid",
            json!([transaction_ids]),
            Vec<CityL1Deposit>
        )
    }

    async fn get_deposit_hash(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(
            self,
            "cr_getDepositHash",
            json!([checkpoint_id, deposit_id]),
            CityHash
        )
    }

    async fn get_deposit_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call!(
            self,
            "cr_getDepositLeafMerkleProof",
            json!([checkpoint_id, deposit_id]),
            CityMerkleProof
        )
    }

    async fn get_block_state(&self, checkpoint_id: u64) -> anyhow::Result<CityL2BlockState> {
        city_external_rpc_call!(
            self,
            "cr_getBlockState",
            json!([checkpoint_id]),
            CityL2BlockState
        )
    }

    async fn get_latest_block_state(&self) -> anyhow::Result<CityL2BlockState> {
        city_external_rpc_call!(self, "cr_getLatestBlockState", json!([]), CityL2BlockState)
    }

    async fn get_city_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(self, "cr_getCityRoot", json!([checkpoint_id]), CityHash)
    }

    async fn get_city_block_script(&self, checkpoint_id: u64) -> anyhow::Result<String> {
        city_external_rpc_call!(
            self,
            "cr_getCityBlockScript",
            json!([checkpoint_id]),
            String
        )
    }

    async fn get_city_block_deposit_address(&self, checkpoint_id: u64) -> anyhow::Result<Hash160> {
        city_external_rpc_call!(
            self,
            "cr_getCityBlockDepositAddress",
            json!([checkpoint_id]),
            Hash160
        )
    }

    async fn get_city_block_deposit_address_string(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<String> {
        city_external_rpc_call!(
            self,
            "cr_getCityBlockDepositAddressString",
            json!([checkpoint_id]),
            String
        )
    }

    async fn get_withdrawal_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(
            self,
            "cr_getWithdrawalTreeRoot",
            json!([checkpoint_id]),
            CityHash
        )
    }

    async fn get_withdrawal_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal> {
        city_external_rpc_call!(
            self,
            "cr_getWithdrawalById",
            json!([checkpoint_id, withdrawal_id]),
            CityL1Withdrawal
        )
    }

    async fn get_withdrawals_by_id(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1Withdrawal>> {
        city_external_rpc_call!(
            self,
            "cr_getWithdrawalsById",
            json!([checkpoint_id, withdrawal_ids]),
            Vec<CityL1Withdrawal>
        )
    }

    async fn get_withdrawal_hash(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(
            self,
            "cr_getWithdrawalHash",
            json!([checkpoint_id, withdrawal_id]),
            CityHash
        )
    }

    async fn get_withdrawal_leaf_merkle_proof(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call!(
            self,
            "cr_getWithdrawalLeafMerkleProof",
            json!([checkpoint_id, withdrawal_id]),
            CityMerkleProof
        )
    }

    async fn register_user<F: RichField>(
        &self,
        req: CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()> {
        city_rpc_call!(self, RequestParams::<F>::RegisterUser(req))
    }

    async fn add_withdrawal<F: RichField>(
        &self,
        req: CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()> {
        city_rpc_call!(self, RequestParams::<F>::AddWithdrawal(req))
    }

    async fn claim_deposit<F: RichField>(
        &self,
        req: CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()> {
        city_rpc_call!(self, RequestParams::<F>::ClaimDeposit(req))
    }

    async fn token_transfer<F: RichField>(
        &self,
        req: CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()> {
        city_rpc_call!(self, RequestParams::<F>::TokenTransfer(req))
    }
}
