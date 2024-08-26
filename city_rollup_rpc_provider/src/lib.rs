use std::sync::{Arc, RwLock, RwLockReadGuard};

use anyhow::Context;
use city_common::data::{kv::SimpleKVPair, u8bytes::U8Bytes};
use city_crypto::hash::base_types::hash160::Hash160;
use city_crypto::hash::base_types::hash256::Hash256;
use city_macros::{city_external_rpc_call, city_external_rpc_call_sync, city_rpc_call, city_rpc_call_sync, async_rpc_call_with_response_handling};
use city_rollup_common::{api::data::{
        block::{
            requested_actions::{
                CityAddWithdrawalRequest, CityClaimDepositRequest, CityRegisterUserRequest,
                CityTokenTransferRequest,
            },
            rpc_request::*,
        },
    store::{CityL1DepositJSON, CityL1Withdrawal, CityL2BlockState, CityUserState},
}, qworker::job_id::QProvingJobDataIDSerializedWrapped};
use city_rollup_core_node::rpc::{
    ExternalRequestParams, Id, RequestParams, ResponseResult, RpcParams, RpcRequest, RpcResponse,
    Version,
};
use city_store::config::{CityHash, CityMerkleProof};
use lazy_static::lazy_static;
use plonky2::hash::hash_types::RichField;
use reqwest::Client;
use serde_json::json;

lazy_static! {
    pub static ref RPC_PROVIDER: RwLock<Option<RpcProvider>> = RwLock::new(None);
}

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
    pub fn get_rpc_provider() -> RwLockReadGuard<'static, Option<RpcProvider>> {
        RPC_PROVIDER
            .read()
            .expect("cannot get RPC_PROVIDER read lock")
    }
    pub fn initialize_rpc_provider(address: &str) {
        let mut rpc_provider = RPC_PROVIDER
            .write()
            .expect("cannot get RPC_PROVIDER write lock");
        *rpc_provider = Some(RpcProvider::new(address));
    }
}

#[derive(Clone, Debug)]
pub struct RpcProviderSync {
    client: Arc<reqwest::blocking::Client>,
    url: &'static str,
}

impl RpcProviderSync {
    pub fn new(url: &str) -> Self {
        Self {
            client: Arc::new(reqwest::blocking::Client::new()),
            url: Box::leak(url.to_string().into_boxed_str()),
        }
    }
}

#[async_trait::async_trait]
pub trait CityRpcProvider {
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;
    async fn get_user_ids_for_public_key(&self, public_key: CityHash) -> anyhow::Result<Vec<u64>>;
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
    ) -> anyhow::Result<CityL1DepositJSON>;

    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>>;

    async fn get_deposit_by_txid(&self, transaction_id: Hash256) -> anyhow::Result<CityL1DepositJSON>;

    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>>;

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

    async fn get_proof_store_value(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> anyhow::Result<U8Bytes>;

    async fn get_proof_store_values(
        &self,
        keys: &[QProvingJobDataIDSerializedWrapped],
    ) -> anyhow::Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>>;

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
    async fn gather_register_user<F: RichField>(
        &self,
    ) -> anyhow::Result<Vec<CityRegisterUserRequest<F>>>;
    async fn gather_claim_deposit<F: RichField>(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<CityClaimDepositRequest>>;
    async fn gather_add_withdrawal<F: RichField>(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<CityAddWithdrawalRequest>>;
    async fn gather_token_transfer<F: RichField>(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<CityTokenTransferRequest>>;
}

pub trait CityRpcProviderSync {
    fn get_user_tree_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;
    fn get_user_ids_for_public_key_sync(&self, public_key: CityHash) -> anyhow::Result<Vec<u64>>;

    fn get_user_by_id_sync(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityUserState>;

    fn get_user_merkle_proof_by_id_sync(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    fn get_user_tree_leaf_sync(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityHash>;

    fn get_user_tree_leaf_merkle_proof_sync(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    fn get_deposit_tree_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    fn get_deposit_by_id_sync(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1DepositJSON>;

    fn get_deposits_by_id_sync(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>>;

    fn get_deposit_by_txid_sync(&self, transaction_id: Hash256) -> anyhow::Result<CityL1DepositJSON>;

    fn get_deposits_by_txid_sync(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>>;

    fn get_deposit_hash_sync(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityHash>;

    fn get_deposit_leaf_merkle_proof_sync(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    fn get_block_state_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityL2BlockState>;

    fn get_latest_block_state_sync(&self) -> anyhow::Result<CityL2BlockState>;

    fn get_city_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    fn get_city_block_script_sync(&self, checkpoint_id: u64) -> anyhow::Result<String>;

    fn get_city_block_deposit_address_sync(&self, checkpoint_id: u64) -> anyhow::Result<Hash160>;

    fn get_city_block_deposit_address_string_sync(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<String>;

    fn get_withdrawal_tree_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash>;

    fn get_withdrawal_by_id_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal>;

    fn get_withdrawals_by_id_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1Withdrawal>>;

    fn get_withdrawal_hash_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityHash>;

    fn get_withdrawal_leaf_merkle_proof_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityMerkleProof>;

    fn get_proof_store_value_sync(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> anyhow::Result<U8Bytes>;

    fn get_proof_store_values_sync(
        &self,
        keys: &[QProvingJobDataIDSerializedWrapped],
    ) -> anyhow::Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>>;

    fn register_user_sync<F: RichField>(
        &self,
        req: CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()>;

    fn add_withdrawal_sync<F: RichField>(
        &self,
        req: CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()>;

    fn claim_deposit_sync<F: RichField>(
        &self,
        req: CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()>;

    fn token_transfer_sync<F: RichField>(
        &self,
        req: CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl CityRpcProvider for RpcProvider {
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call!(self, "cr_getUserTreeRoot", json!([checkpoint_id]), CityHash)
    }

    async fn get_user_ids_for_public_key(&self, public_key: CityHash) -> anyhow::Result<Vec<u64>> {
        city_external_rpc_call!(self, "cr_getUserIdsForPublicKey", json!([public_key]), Vec<u64>)
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
    ) -> anyhow::Result<CityL1DepositJSON> {
        city_external_rpc_call!(
            self,
            "cr_getDepositById",
            json!([checkpoint_id, deposit_id]),
            CityL1DepositJSON
        )
    }

    async fn get_deposits_by_id(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>> {
        city_external_rpc_call!(
            self,
            "cr_getDepositsById",
            json!([checkpoint_id, deposit_ids]),
            Vec<CityL1DepositJSON>
        )
    }

    async fn get_deposit_by_txid(&self, transaction_id: Hash256) -> anyhow::Result<CityL1DepositJSON> {
        city_external_rpc_call!(
            self,
            "cr_getDepositByTxid",
            json!([transaction_id]),
            CityL1DepositJSON
        )
    }

    async fn get_deposits_by_txid(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>> {
        city_external_rpc_call!(
            self,
            "cr_getDepositsByTxid",
            json!([transaction_ids]),
            Vec<CityL1DepositJSON>
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

    async fn get_proof_store_value(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> anyhow::Result<U8Bytes> {
        city_external_rpc_call!(
            self,
            "cr_getProofStoreValue",
            json!([key]),
            U8Bytes
        )
    }
    async fn get_proof_store_values(
        &self,
        keys: &[QProvingJobDataIDSerializedWrapped],
    ) -> anyhow::Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>> {
        city_external_rpc_call!(
            self,
            "cr_getProofStoreValues",
            json!([keys]),
            Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>
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
    async fn gather_register_user<F: RichField>(
        &self,
    ) -> anyhow::Result<Vec<CityRegisterUserRequest<F>>> {
        let ret = {
            let response = self
                .client
                .post(self.url)
                .json(&RpcRequest {
                    jsonrpc: Version::V2,
                    request: RequestParams::<F>::GatherRegisterUser,
                    id: Id::Number(1),
                })
                .send()
                .await?
                .json::<RpcResponse<Vec<CityRegisterUserRequest<F>>>>()
                .await?;

            if let ResponseResult::Success(s) = response.result {
                Ok(s)
            } else {
                Err(anyhow::format_err!("rpc call failed"))
            }
        };

        ret.context("gather_register_user failed")
    }
    async fn gather_claim_deposit<F: RichField>(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<CityClaimDepositRequest>> {
        let ret = async_rpc_call_with_response_handling!(
            self,
            RequestParams::<F,>::GatherClaimDeposit(checkpoint_id),
            Vec<CityClaimDepositRequest,>
        );

        ret.context("gather_claim_deposit failed")
    }
    async fn gather_add_withdrawal<F: RichField>(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<CityAddWithdrawalRequest>> {
        let ret = async_rpc_call_with_response_handling!(
            self,
            RequestParams::<F,>::GatherAddWithdrawal(checkpoint_id),
            Vec<CityAddWithdrawalRequest,>
        );
        ret.context("gather_add_withdrawal failed")
    }
    async fn gather_token_transfer<F: RichField>(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<CityTokenTransferRequest>> {
        let ret = async_rpc_call_with_response_handling!(
            self,
            RequestParams::<F,>::GatherTokenTransfer(checkpoint_id),
            Vec<CityTokenTransferRequest,>
        );
        ret.context("gather_token_transfer failed")
    }
}

impl CityRpcProviderSync for RpcProviderSync {
    fn get_user_tree_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(self, "cr_getUserTreeRoot", json!([checkpoint_id]), CityHash)
    }

    fn get_user_ids_for_public_key_sync(&self, public_key: CityHash) -> anyhow::Result<Vec<u64>> {
        city_external_rpc_call_sync!(self, "cr_getUserIdsForPublicKey", json!([public_key]), Vec<u64>)
    }

    fn get_user_by_id_sync(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityUserState> {
        city_external_rpc_call_sync!(
            self,
            "cr_getUserById",
            json!([checkpoint_id, user_id]),
            CityUserState
        )
    }

    fn get_user_merkle_proof_by_id_sync(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call_sync!(
            self,
            "cr_getUserMerkleProofById",
            json!([checkpoint_id, user_id]),
            CityMerkleProof
        )
    }

    fn get_user_tree_leaf_sync(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(
            self,
            "cr_getUserTreeLeaf",
            json!([checkpoint_id, leaf_id]),
            CityHash
        )
    }

    fn get_user_tree_leaf_merkle_proof_sync(
        &self,
        checkpoint_id: u64,
        leaf_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call_sync!(
            self,
            "cr_getUserTreeLeafMeckleProof",
            json!([checkpoint_id, leaf_id]),
            CityMerkleProof
        )
    }

    fn get_deposit_tree_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositTreeRoot",
            json!([checkpoint_id]),
            CityHash
        )
    }

    fn get_deposit_by_id_sync(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1DepositJSON> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositById",
            json!([checkpoint_id, deposit_id]),
            CityL1DepositJSON
        )
    }

    fn get_deposits_by_id_sync(
        &self,
        checkpoint_id: u64,
        deposit_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositsById",
            json!([checkpoint_id, deposit_ids]),
            Vec<CityL1DepositJSON>
        )
    }

    fn get_deposit_by_txid_sync(&self, transaction_id: Hash256) -> anyhow::Result<CityL1DepositJSON> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositByTxid",
            json!([transaction_id]),
            CityL1DepositJSON
        )
    }

    fn get_deposits_by_txid_sync(
        &self,
        transaction_ids: Vec<Hash256>,
    ) -> anyhow::Result<Vec<CityL1DepositJSON>> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositsByTxid",
            json!([transaction_ids]),
            Vec<CityL1DepositJSON>
        )
    }

    fn get_deposit_hash_sync(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositHash",
            json!([checkpoint_id, deposit_id]),
            CityHash
        )
    }

    fn get_deposit_leaf_merkle_proof_sync(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call_sync!(
            self,
            "cr_getDepositLeafMerkleProof",
            json!([checkpoint_id, deposit_id]),
            CityMerkleProof
        )
    }

    fn get_block_state_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityL2BlockState> {
        city_external_rpc_call_sync!(
            self,
            "cr_getBlockState",
            json!([checkpoint_id]),
            CityL2BlockState
        )
    }

    fn get_latest_block_state_sync(&self) -> anyhow::Result<CityL2BlockState> {
        city_external_rpc_call_sync!(self, "cr_getLatestBlockState", json!([]), CityL2BlockState)
    }

    fn get_city_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(self, "cr_getCityRoot", json!([checkpoint_id]), CityHash)
    }

    fn get_city_block_script_sync(&self, checkpoint_id: u64) -> anyhow::Result<String> {
        city_external_rpc_call_sync!(
            self,
            "cr_getCityBlockScript",
            json!([checkpoint_id]),
            String
        )
    }

    fn get_city_block_deposit_address_sync(&self, checkpoint_id: u64) -> anyhow::Result<Hash160> {
        city_external_rpc_call_sync!(
            self,
            "cr_getCityBlockDepositAddress",
            json!([checkpoint_id]),
            Hash160
        )
    }

    fn get_city_block_deposit_address_string_sync(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<String> {
        city_external_rpc_call_sync!(
            self,
            "cr_getCityBlockDepositAddressString",
            json!([checkpoint_id]),
            String
        )
    }

    fn get_withdrawal_tree_root_sync(&self, checkpoint_id: u64) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(
            self,
            "cr_getWithdrawalTreeRoot",
            json!([checkpoint_id]),
            CityHash
        )
    }

    fn get_withdrawal_by_id_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal> {
        city_external_rpc_call_sync!(
            self,
            "cr_getWithdrawalById",
            json!([checkpoint_id, withdrawal_id]),
            CityL1Withdrawal
        )
    }

    fn get_withdrawals_by_id_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_ids: Vec<u64>,
    ) -> anyhow::Result<Vec<CityL1Withdrawal>> {
        city_external_rpc_call_sync!(
            self,
            "cr_getWithdrawalsById",
            json!([checkpoint_id, withdrawal_ids]),
            Vec<CityL1Withdrawal>
        )
    }

    fn get_withdrawal_hash_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityHash> {
        city_external_rpc_call_sync!(
            self,
            "cr_getWithdrawalHash",
            json!([checkpoint_id, withdrawal_id]),
            CityHash
        )
    }

    fn get_withdrawal_leaf_merkle_proof_sync(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
    ) -> anyhow::Result<CityMerkleProof> {
        city_external_rpc_call_sync!(
            self,
            "cr_getWithdrawalLeafMerkleProof",
            json!([checkpoint_id, withdrawal_id]),
            CityMerkleProof
        )
    }

    fn get_proof_store_value_sync(
        &self,
        key: QProvingJobDataIDSerializedWrapped,
    ) -> anyhow::Result<U8Bytes> {
        city_external_rpc_call_sync!(
            self,
            "cr_getProofStoreValue",
            json!([key]),
            U8Bytes
        )
    }

    fn get_proof_store_values_sync(
        &self,
        keys: &[QProvingJobDataIDSerializedWrapped],
    ) -> anyhow::Result<Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>> {
        city_external_rpc_call_sync!(
            self,
            "cr_getProofStoreValues",
            json!([keys]),
            Vec<SimpleKVPair<QProvingJobDataIDSerializedWrapped, U8Bytes>>
        )
    }

    fn register_user_sync<F: RichField>(
        &self,
        req: CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()> {
        city_rpc_call_sync!(self, RequestParams::<F>::RegisterUser(req))
    }

    fn add_withdrawal_sync<F: RichField>(
        &self,
        req: CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()> {
        city_rpc_call_sync!(self, RequestParams::<F>::AddWithdrawal(req))
    }

    fn claim_deposit_sync<F: RichField>(
        &self,
        req: CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()> {
        city_rpc_call_sync!(self, RequestParams::<F>::ClaimDeposit(req))
    }

    fn token_transfer_sync<F: RichField>(
        &self,
        req: CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()> {
        city_rpc_call_sync!(self, RequestParams::<F>::TokenTransfer(req))
    }
}
