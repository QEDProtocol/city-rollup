use plonky2::hash::hash_types::RichField;

use crate::{
    api::data::{
        block::{
            requested_actions::{
                CityAddWithdrawalRequest, CityClaimDepositRequest, CityRegisterUserRequest,
                CityTokenTransferRequest,
            },
            rpc_request::{
                CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest,
                CityRegisterUserRPCRequest, CityTokenTransferRPCRequest,
            },
        },
        store::{CityL1Deposit, CityL1Withdrawal, CityL2BlockState, CityUserState},
    },
    qworker::job_id::QProvingJobDataID,
};

pub trait OrchestratorRPCEventSenderSync<F: RichField> {
    fn notify_rpc_claim_deposit(
        &mut self,
        event: &CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()>;
    fn notify_rpc_register_user(
        &mut self,
        event: &CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()>;
    fn notify_rpc_add_withdrawal(
        &mut self,
        event: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()>;
    fn notify_rpc_token_transfer(
        &mut self,
        event: &CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait OrchestratorRPCEventSenderAsync<F: RichField> {
    async fn notify_rpc_claim_deposit_async(
        &mut self,
        event: &CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()>;

    async fn notify_rpc_register_user_async(
        &mut self,
        event: &CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()>;

    async fn notify_rpc_add_withdrawal_async(
        &mut self,
        event: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()>;

    async fn notify_rpc_token_transfer_async(
        &mut self,
        event: &CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()>;
    async fn notify_rpc_produce_block_async(&mut self) -> anyhow::Result<()>;
}

pub trait OrchestratorEventSenderSync<F: RichField> {
    fn notify_claim_deposit(&mut self, event: &CityClaimDepositRequest) -> anyhow::Result<()>;
    fn notify_register_user(&mut self, event: &CityRegisterUserRequest<F>) -> anyhow::Result<()>;
    fn notify_add_withdrawal(&mut self, event: &CityAddWithdrawalRequest) -> anyhow::Result<()>;
    fn notify_token_transfer(&mut self, event: &CityTokenTransferRequest) -> anyhow::Result<()>;
    fn notify_produce_block(&mut self) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait OrchestratorEventSenderAsync<F: RichField> {
    async fn notify_claim_deposit_async(
        &mut self,
        event: &CityClaimDepositRequest,
    ) -> anyhow::Result<()>;

    async fn notify_register_user_async(
        &mut self,
        event: &CityRegisterUserRequest<F>,
    ) -> anyhow::Result<()>;

    async fn notify_add_withdrawal_async(
        &mut self,
        event: &CityAddWithdrawalRequest,
    ) -> anyhow::Result<()>;

    async fn notify_token_transfer_async(
        &mut self,
        event: &CityTokenTransferRequest,
    ) -> anyhow::Result<()>;
    async fn notify_produce_block_async(&mut self) -> anyhow::Result<()>;
}

pub trait OrchestratorEventReceiverSync<F: RichField> {
    fn flush_claim_deposits(&mut self) -> anyhow::Result<Vec<CityClaimDepositRequest>>;

    fn flush_register_users(&mut self) -> anyhow::Result<Vec<CityRegisterUserRequest<F>>>;

    fn flush_add_withdrawals(&mut self) -> anyhow::Result<Vec<CityAddWithdrawalRequest>>;

    fn flush_token_transfers(&mut self) -> anyhow::Result<Vec<CityTokenTransferRequest>>;
    fn wait_for_produce_block(&mut self) -> anyhow::Result<bool>;
}
pub trait WorkerEventReceiverSync {
    fn wait_for_next_job(&mut self) -> anyhow::Result<QProvingJobDataID>;
    fn enqueue_jobs(&mut self, jobs: &[QProvingJobDataID]) -> anyhow::Result<()>;
    fn notify_core_goal_completed(&mut self, job: QProvingJobDataID) -> anyhow::Result<()>;
}

pub trait WorkerEventTransmitterSync {
    fn notify_jobs(&mut self, jobs: &[QProvingJobDataID]) -> anyhow::Result<QProvingJobDataID>;
}

pub trait LastBlockNodeStateQueryAPISync {
    fn get_user(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<CityUserState>;
    fn get_deposit(&self, checkpoint_id: u64, deposit_id: u64) -> anyhow::Result<CityL1Deposit>;
    fn get_withdrawal(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal>;
    fn get_block(&self, checkpoint_id: u64, deposit_id: u64) -> anyhow::Result<CityL2BlockState>;
}

#[async_trait::async_trait]
pub trait LastBlockNodeStateQueryAPIAsync {
    fn get_user_async(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<CityUserState>;
    fn get_deposit_async(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1Deposit>;
    fn get_withdrawal_async(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL1Withdrawal>;
    fn get_block_async(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
    ) -> anyhow::Result<CityL2BlockState>;
}
pub trait CurrentBlockNodeStateQueryAPIReaderSync {
    fn get_user_balance(&self, user_id: u64) -> anyhow::Result<u64>;
    fn get_withdrawal_count(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
    fn get_user_count(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
}

pub trait CurrentBlockNodeStateQueryAPIWriterSync {
    fn inc_user_balance(&self, user_id: u64, amount: u64) -> anyhow::Result<u64>;
    fn dec_user_balance(&self, user_id: u64, amount: u64) -> anyhow::Result<u64>;
    fn inc_withdrawal_count(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
    fn inc_user_count(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
}
